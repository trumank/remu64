use anyhow::Result;
use remu64::memory::MemoryTrait;
use remu64_protocol::{ProtocolMessage, write_message_to_stream};
use std::io::{ErrorKind, Read};
use std::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

struct Connection {
    stream: TcpStream,
    read_buffer: Vec<u8>,
}

impl Connection {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream,
            read_buffer: Vec::new(),
        }
    }

    fn try_read_message(&mut self) -> Result<Option<ProtocolMessage>, std::io::Error> {
        // Read available data into buffer
        let mut temp_buf = [0u8; 4096];
        match self.stream.read(&mut temp_buf) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "Connection closed",
                ));
            }
            Ok(n) => self.read_buffer.extend_from_slice(&temp_buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
            Err(e) => return Err(e),
        }

        if self.read_buffer.len() >= 4 {
            let expected_len =
                u32::from_le_bytes(self.read_buffer[0..4].try_into().unwrap()) as usize;
            if self.read_buffer.len() >= expected_len + 4 {
                let msg = ProtocolMessage::deserialize(&self.read_buffer[4..expected_len + 4]);
                self.read_buffer.drain(0..expected_len + 4);

                match msg {
                    Ok(message) => return Ok(Some(message)),
                    Err(e) => return Err(std::io::Error::new(ErrorKind::InvalidData, e)),
                }
            }
        }
        Ok(None) // Need more data for message
    }
}

pub struct ProtocolServer {
    listener: TcpListener,
    connections: Vec<Connection>,
}

impl ProtocolServer {
    pub fn new(port: u16) -> Result<Self> {
        let listener = TcpListener::bind(format!("127.0.0.1:{}", port))?;
        listener.set_nonblocking(true)?;

        info!("Protocol server listening on port {}", port);

        Ok(ProtocolServer {
            listener,
            connections: Vec::new(),
        })
    }

    pub fn process_requests<M: MemoryTrait>(&mut self, memory: &M) {
        // Accept new connections
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    debug!("New connection from {}", addr);
                    if let Err(e) = stream.set_nonblocking(true) {
                        error!("Failed to set stream nonblocking: {}", e);
                        continue;
                    }
                    stream.set_nodelay(true).unwrap();
                    self.connections.push(Connection::new(stream));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    break;
                }
            }
        }

        // Process requests from existing connections
        self.connections.retain_mut(|conn| {
            loop {
                match conn.try_read_message() {
                    Ok(Some(message)) => {
                        let response = match message {
                            ProtocolMessage::ReadRequest { address, size } => {
                                // debug!("Read request: addr=0x{:x}, size={}", address, size);

                                let mut buffer = vec![0u8; size as usize];
                                let result = memory.read(address, &mut buffer);

                                match result {
                                    Ok(()) => ProtocolMessage::ReadResponse { result: Ok(buffer) },
                                    Err(e) => ProtocolMessage::ReadResponse {
                                        result: Err(format!("Read failed: {}", e)),
                                    },
                                }
                            }
                            ProtocolMessage::WriteRequest { address, data } => {
                                debug!(
                                    "Write request: addr=0x{:x}, size={} (rejected - read-only)",
                                    address,
                                    data.len()
                                );

                                ProtocolMessage::WriteResponse {
                                    result: Err(
                                        "Write operations not supported in TUI mode".to_string()
                                    ),
                                }
                            }
                            _ => {
                                warn!("Unexpected message type from client");
                                break; // Keep connection
                            }
                        };

                        // Send response
                        if let Err(e) = write_message_to_stream(&mut conn.stream, &response) {
                            debug!("Failed to send response: {}", e);
                            return false; // Remove connection
                        }
                    }
                    Ok(None) => break, // No complete message yet
                    Err(e) => {
                        debug!("Connection closed: {}", e);
                        return false; // Remove connection
                    }
                };
            }
            true
        });
    }
}
