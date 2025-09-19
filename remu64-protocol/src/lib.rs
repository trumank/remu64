use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Result as IoResult, Write};

#[derive(Debug, Clone, PartialEq)]
pub enum ProtocolMessage {
    ReadRequest { address: u64, size: u32 },
    ReadResponse { result: Result<Vec<u8>, String> },
    WriteRequest { address: u64, data: Vec<u8> },
    WriteResponse { result: Result<(), String> },
}

const READ_REQUEST: u8 = 1;
const READ_RESPONSE: u8 = 2;
const WRITE_REQUEST: u8 = 3;
const WRITE_RESPONSE: u8 = 4;

const SUCCESS: u8 = 0;
const ERROR: u8 = 1;

impl ProtocolMessage {
    pub fn serialize(&self) -> IoResult<Vec<u8>> {
        let mut buf = Vec::new();

        match self {
            ProtocolMessage::ReadRequest { address, size } => {
                buf.write_u8(READ_REQUEST)?;
                buf.write_u64::<LittleEndian>(*address)?;
                buf.write_u32::<LittleEndian>(*size)?;
            }
            ProtocolMessage::ReadResponse { result } => {
                buf.write_u8(READ_RESPONSE)?;
                match result {
                    Ok(data) => {
                        buf.write_u8(SUCCESS)?;
                        buf.write_u32::<LittleEndian>(data.len() as u32)?;
                        buf.write_all(data)?;
                    }
                    Err(err) => {
                        buf.write_u8(ERROR)?;
                        let err_bytes = err.as_bytes();
                        buf.write_u32::<LittleEndian>(err_bytes.len() as u32)?;
                        buf.write_all(err_bytes)?;
                    }
                }
            }
            ProtocolMessage::WriteRequest { address, data } => {
                buf.write_u8(WRITE_REQUEST)?;
                buf.write_u64::<LittleEndian>(*address)?;
                buf.write_u32::<LittleEndian>(data.len() as u32)?;
                buf.write_all(data)?;
            }
            ProtocolMessage::WriteResponse { result } => {
                buf.write_u8(WRITE_RESPONSE)?;
                match result {
                    Ok(()) => buf.write_u8(SUCCESS)?,
                    Err(err) => {
                        buf.write_u8(ERROR)?;
                        let err_bytes = err.as_bytes();
                        buf.write_u32::<LittleEndian>(err_bytes.len() as u32)?;
                        buf.write_all(err_bytes)?;
                    }
                }
            }
        }

        Ok(buf)
    }

    pub fn deserialize(data: &[u8]) -> IoResult<Self> {
        let mut cursor = Cursor::new(data);

        let msg_type = cursor.read_u8()?;

        match msg_type {
            READ_REQUEST => {
                let address = cursor.read_u64::<LittleEndian>()?;
                let size = cursor.read_u32::<LittleEndian>()?;
                Ok(ProtocolMessage::ReadRequest { address, size })
            }
            READ_RESPONSE => {
                let status = cursor.read_u8()?;
                let data_len = cursor.read_u32::<LittleEndian>()? as usize;

                let mut data_buf = vec![0u8; data_len];
                cursor.read_exact(&mut data_buf)?;

                let result = if status == SUCCESS {
                    Ok(data_buf)
                } else {
                    Err(String::from_utf8_lossy(&data_buf).to_string())
                };

                Ok(ProtocolMessage::ReadResponse { result })
            }
            WRITE_REQUEST => {
                let address = cursor.read_u64::<LittleEndian>()?;
                let data_len = cursor.read_u32::<LittleEndian>()? as usize;

                let mut data_buf = vec![0u8; data_len];
                cursor.read_exact(&mut data_buf)?;

                Ok(ProtocolMessage::WriteRequest {
                    address,
                    data: data_buf,
                })
            }
            WRITE_RESPONSE => {
                let status = cursor.read_u8()?;

                let result = if status == SUCCESS {
                    Ok(())
                } else {
                    let err_len = cursor.read_u32::<LittleEndian>()? as usize;
                    let mut err_buf = vec![0u8; err_len];
                    cursor.read_exact(&mut err_buf)?;
                    Err(String::from_utf8_lossy(&err_buf).to_string())
                };

                Ok(ProtocolMessage::WriteResponse { result })
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Unknown message type: {}", msg_type),
            )),
        }
    }
}

pub fn read_message_from_stream<R: Read>(mut stream: R) -> IoResult<ProtocolMessage> {
    let msg_len = stream.read_u32::<LittleEndian>()? as usize;
    let mut msg_buf = vec![0u8; msg_len];
    stream.read_exact(&mut msg_buf)?;
    ProtocolMessage::deserialize(&msg_buf)
}

pub fn write_message_to_stream<W: Write>(mut stream: W, message: &ProtocolMessage) -> IoResult<()> {
    let serialized = message.serialize()?;
    stream.write_u32::<LittleEndian>(serialized.len() as u32)?;
    stream.write_all(&serialized)?;
    stream.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_request_roundtrip() {
        let msg = ProtocolMessage::ReadRequest {
            address: 0x140001000,
            size: 256,
        };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_read_response_success_roundtrip() {
        let msg = ProtocolMessage::ReadResponse {
            result: Ok(vec![0x90, 0x90, 0x90, 0x90]),
        };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_read_response_error_roundtrip() {
        let msg = ProtocolMessage::ReadResponse {
            result: Err("Access denied".to_string()),
        };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_write_request_roundtrip() {
        let msg = ProtocolMessage::WriteRequest {
            address: 0x7ff00000,
            data: vec![0xeb, 0xfe], // jmp $
        };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_write_response_success_roundtrip() {
        let msg = ProtocolMessage::WriteResponse { result: Ok(()) };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }

    #[test]
    fn test_write_response_error_roundtrip() {
        let msg = ProtocolMessage::WriteResponse {
            result: Err("Write protected".to_string()),
        };

        let serialized = msg.serialize().unwrap();
        let deserialized = ProtocolMessage::deserialize(&serialized).unwrap();

        assert_eq!(msg, deserialized);
    }
}
