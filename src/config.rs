use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub devices: HashMap<String, String>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Self {
        let path = path.as_ref();

        if !path.exists() {
            eprintln!(
                "Warning: config file '{}' not found, starting with empty aliases",
                path.display()
            );
            return Self {
                devices: HashMap::new(),
            };
        }

        match fs::read_to_string(path) {
            Ok(content) => match serde_yaml::from_str(&content) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("Warning: failed to parse config file: {error}");
                    Self {
                        devices: HashMap::new(),
                    }
                }
            },
            Err(error) => {
                eprintln!("Warning: failed to read config file: {error}");
                Self {
                    devices: HashMap::new(),
                }
            }
        }
    }

    pub fn resolve_device(&self, device: &str) -> Option<String> {
        if is_valid_mac(device) {
            return Some(device.to_uppercase());
        }

        self.devices.get(device).map(|mac| mac.to_uppercase())
    }
}

pub fn is_valid_mac(mac: &str) -> bool {
    let parts: Vec<&str> = mac.split(':').collect();

    if parts.len() != 6 {
        return false;
    }

    parts
        .iter()
        .all(|part| part.len() == 2 && part.chars().all(|c| c.is_ascii_hexdigit()))
}
