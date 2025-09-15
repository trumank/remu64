use anyhow::{Result, anyhow};
use notify_debouncer_full::{
    DebouncedEvent, Debouncer, RecommendedCache, new_debouncer,
    notify::{event::*, *},
};
use remu64::Register;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::Path, sync::mpsc, time::Duration};

use remu64_tui::{InstructionAction, InstructionActions};

/// Configuration for the TUI application
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Path to the minidump file
    pub minidump_path: String,

    /// Function address to execute (in hex format like "0x140001000")
    #[serde(with = "hex_string")]
    pub function_address: u64,

    /// Stack configuration
    #[serde(default)]
    pub stack: StackConfig,

    /// Initial register values (register name -> value)
    #[serde(default, with = "register_map")]
    pub registers: HashMap<Register, u64>,

    /// Instruction actions (skip, etc.) by instruction index
    #[serde(default, with = "instruction_actions_map")]
    pub instruction_actions: InstructionActions,

    /// Tracing configuration
    #[serde(default)]
    pub tracing: TracingConfig,
}

/// Stack configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackConfig {
    /// Stack base address (hex string like "0x7fff_f000_0000")
    #[serde(default = "StackConfig::default_stack_base", with = "hex_string")]
    pub base_address: u64,

    /// Stack size in bytes (hex string like "0x100000")
    #[serde(default = "StackConfig::default_stack_size", with = "hex_string")]
    pub size: u64,

    /// Initial stack pointer offset from base (hex string like "0x1000")
    #[serde(default = "StackConfig::default_initial_offset", with = "hex_string")]
    pub initial_offset: u64,
}

impl Default for StackConfig {
    fn default() -> Self {
        Self {
            base_address: Self::default_stack_base(),
            size: Self::default_stack_size(),
            initial_offset: Self::default_initial_offset(),
        }
    }
}

impl StackConfig {
    fn default_stack_base() -> u64 {
        0x7fff_f000_0000
    }

    fn default_stack_size() -> u64 {
        0x100000
    }

    fn default_initial_offset() -> u64 {
        0x1000
    }
}

/// Instruction action configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InstructionActionConfig {
    Skip,
}

impl From<InstructionActionConfig> for InstructionAction {
    fn from(config: InstructionActionConfig) -> Self {
        match config {
            InstructionActionConfig::Skip => InstructionAction::Skip,
        }
    }
}

/// Tracing configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracingConfig {
    /// Maximum number of instructions to trace
    #[serde(default = "TracingConfig::default_max_instructions")]
    pub max_instructions: usize,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            max_instructions: Self::default_max_instructions(),
        }
    }
}

impl TracingConfig {
    fn default_max_instructions() -> usize {
        10000
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let contents = fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read config file {:?}: {}", path.as_ref(), e))?;

        let config: Config = toml::from_str(&contents)
            .map_err(|e| anyhow!("Failed to parse config file {:?}: {}", path.as_ref(), e))?;

        Ok(config)
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let contents = toml::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize config: {}", e))?;

        fs::write(&path, contents)
            .map_err(|e| anyhow!("Failed to write config file {:?}: {}", path.as_ref(), e))?;

        Ok(())
    }

    /// Create a sample configuration file
    pub fn create_sample() -> Self {
        let mut registers = HashMap::new();
        registers.insert(Register::RCX, 0x289836c6200);

        let mut instruction_actions = HashMap::new();
        instruction_actions.insert(5, vec![InstructionAction::Skip]);
        instruction_actions.insert(10, vec![InstructionAction::Skip]);

        Config {
            minidump_path: "path/to/minidump.dmp".to_string(),
            function_address: 0x140001000,
            stack: StackConfig::default(),
            registers,
            instruction_actions,
            tracing: TracingConfig::default(),
        }
    }
}

/// Parse a hex string that may have 0x prefix and underscores for readability
fn parse_hex(s: &str) -> Result<u64> {
    // Remove underscores for readability
    let cleaned = s.replace('_', "");

    if let Some(hex_str) = cleaned.strip_prefix("0x") {
        u64::from_str_radix(hex_str, 16).map_err(|e| anyhow!("Invalid hex string '{}': {}", s, e))
    } else {
        u64::from_str_radix(&cleaned, 16).map_err(|e| anyhow!("Invalid hex string '{}': {}", s, e))
    }
}

/// Parse register name string to Register enum
fn parse_register_name(name: &str) -> Result<Register> {
    match name.to_uppercase().as_str() {
        "RAX" => Ok(Register::RAX),
        "RBX" => Ok(Register::RBX),
        "RCX" => Ok(Register::RCX),
        "RDX" => Ok(Register::RDX),
        "RSI" => Ok(Register::RSI),
        "RDI" => Ok(Register::RDI),
        "RSP" => Ok(Register::RSP),
        "RBP" => Ok(Register::RBP),
        "R8" => Ok(Register::R8),
        "R9" => Ok(Register::R9),
        "R10" => Ok(Register::R10),
        "R11" => Ok(Register::R11),
        "R12" => Ok(Register::R12),
        "R13" => Ok(Register::R13),
        "R14" => Ok(Register::R14),
        "R15" => Ok(Register::R15),
        "RIP" => Ok(Register::RIP),
        _ => Err(anyhow!("Unknown register name: {}", name)),
    }
}

type RecommendedDebouncer = Debouncer<RecommendedWatcher, RecommendedCache>;

/// Structure to support hot-reloading
/// Contains metadata about the config file for change detection
pub struct ConfigLoader {
    pub config_path: std::path::PathBuf,
    pub config: Config,
    /// File watcher for hot-reload capability
    #[allow(unused)]
    watcher: Option<RecommendedDebouncer>,
    /// Channel to receive file change events
    change_receiver: Option<
        mpsc::Receiver<Result<Vec<DebouncedEvent>, Vec<notify_debouncer_full::notify::Error>>>,
    >,
}

impl ConfigLoader {
    pub fn new<P: AsRef<Path>>(config_path: P) -> Result<Self> {
        let config_path = config_path.as_ref().to_path_buf();
        let config = Config::load_from_file(&config_path)?;

        let (tx, rx) = mpsc::channel();
        let mut watcher = new_debouncer(Duration::from_millis(50), None, tx)?;

        watcher
            .watch(config_path.parent().unwrap(), RecursiveMode::NonRecursive)
            .map_err(|e| anyhow!("Failed to watch config file {:?}: {}", config_path, e))?;

        Ok(Self {
            config_path,
            config,
            watcher: Some(watcher),
            change_receiver: Some(rx),
        })
    }

    /// Force reload the config
    pub fn reload(&mut self) -> Result<()> {
        self.config = Config::load_from_file(&self.config_path)?;
        Ok(())
    }

    /// Check for config changes via file watcher (non-blocking)
    pub fn check_watcher_changes(&mut self) -> Result<bool> {
        if let Some(ref receiver) = self.change_receiver {
            // Check for any pending file events (non-blocking)
            match receiver.try_recv() {
                Ok(Ok(events)) => {
                    if events.iter().any(|e| {
                        matches!(
                            e.kind,
                            EventKind::Modify(_)
                                | EventKind::Access(AccessKind::Close(AccessMode::Write))
                        ) && e
                            .paths
                            .iter()
                            .any(|p| p.canonicalize().ok() == self.config_path.canonicalize().ok())
                    }) {
                        match self.reload() {
                            Ok(()) => {
                                tracing::info!("Config file reloaded successfully");
                                return Ok(true);
                            }
                            Err(e) => {
                                tracing::warn!("Failed to reload config: {}", e);
                                return Err(e);
                            }
                        }
                    }
                }
                Ok(Err(errors)) => {
                    for err in errors {
                        tracing::warn!("File watcher error: {}", err);
                    }
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    tracing::warn!("File watcher channel disconnected");
                    return Err(anyhow!("File watcher channel disconnected"));
                }
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0x1000").unwrap(), 0x1000);
        assert_eq!(parse_hex("1000").unwrap(), 0x1000);
        assert_eq!(parse_hex("0x7fff_f000_0000").unwrap(), 0x7fff_f000_0000);
        assert_eq!(parse_hex("0x140001000").unwrap(), 0x140001000);
    }

    #[test]
    fn test_parse_register_name() {
        assert_eq!(parse_register_name("RAX").unwrap(), Register::RAX);
        assert_eq!(parse_register_name("rax").unwrap(), Register::RAX);
        assert_eq!(parse_register_name("RCX").unwrap(), Register::RCX);
        assert!(parse_register_name("INVALID").is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::create_sample();
        let toml_str = toml::to_string_pretty(&config).unwrap();
        let parsed_config: Config = toml::from_str(&toml_str).unwrap();

        assert_eq!(config.minidump_path, parsed_config.minidump_path);
        assert_eq!(config.function_address, parsed_config.function_address);
        assert_eq!(config.stack.base_address, parsed_config.stack.base_address);
    }
}

/// Custom deserializer for hex strings
mod hex_string {
    use super::parse_hex;
    use anyhow::Result;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: String = String::deserialize(deserializer)?;
        parse_hex(&hex_str).map_err(serde::de::Error::custom)
    }

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        format!("0x{:x}", value).serialize(serializer)
    }
}

/// Custom deserializer for register map (string keys to Register enum)
mod register_map {
    use super::{parse_hex, parse_register_name};
    use remu64::Register;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<HashMap<Register, u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: HashMap<String, String> = HashMap::deserialize(deserializer)?;
        let mut register_map = HashMap::new();

        for (reg_name, value_str) in string_map {
            let register = parse_register_name(&reg_name).map_err(serde::de::Error::custom)?;
            let value = parse_hex(&value_str).map_err(serde::de::Error::custom)?;
            register_map.insert(register, value);
        }

        Ok(register_map)
    }

    pub fn serialize<S>(map: &HashMap<Register, u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let string_map: HashMap<String, String> = map
            .iter()
            .map(|(reg, value)| (format!("{:?}", reg), format!("0x{:x}", value)))
            .collect();
        string_map.serialize(serializer)
    }
}

/// Custom deserializer for instruction actions map
mod instruction_actions_map {
    use super::{InstructionAction, InstructionActionConfig};
    use remu64_tui::InstructionActions;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::collections::HashMap;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<InstructionActions, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string_map: HashMap<String, Vec<InstructionActionConfig>> =
            HashMap::deserialize(deserializer)?;
        let mut actions = HashMap::new();

        for (index_str, config_actions) in string_map {
            let index: usize = index_str.parse().map_err(|e| {
                serde::de::Error::custom(format!(
                    "Invalid instruction index '{}': {}",
                    index_str, e
                ))
            })?;

            let runtime_actions: Vec<InstructionAction> = config_actions
                .into_iter()
                .map(|config| config.into())
                .collect();

            if !runtime_actions.is_empty() {
                actions.insert(index, runtime_actions);
            }
        }

        Ok(actions)
    }

    pub fn serialize<S>(map: &InstructionActions, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let toml_map: HashMap<String, Vec<HashMap<String, String>>> = map
            .iter()
            .map(|(index, actions)| {
                let action_objects: Vec<HashMap<String, String>> = actions
                    .iter()
                    .map(|action| {
                        let mut obj = HashMap::new();
                        obj.insert(
                            "type".to_string(),
                            match action {
                                InstructionAction::Skip => "skip".to_string(),
                            },
                        );
                        obj
                    })
                    .collect();
                (index.to_string(), action_objects)
            })
            .collect();

        toml_map.serialize(serializer)
    }
}
