use anyhow::Result;
use log::error;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;

// --- UID Map Logic ---
pub struct UidMap {
    pub hostnames: HashMap<u8, String>,
}

impl UidMap {
    pub fn new() -> Self {
        Self {
            hostnames: HashMap::new(),
        }
    }

    pub fn load(&mut self, path: &str) -> Result<()> {
        if !Path::new(path).exists() {
            return Ok(());
        }
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        self.hostnames.clear();

        for (line_no, line) in reader.lines().enumerate() {
            let line = line?;
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                error!(
                    "UID Map Warning: Malformed line {}: needs 'UID HOSTNAME'",
                    line_no + 1
                );
                continue;
            }

            let uid = match parts[0].parse::<u8>() {
                Ok(u) => u,
                Err(e) => {
                    error!(
                        "UID Map Warning: Invalid UID '{}' at line {}: {}",
                        parts[0],
                        line_no + 1,
                        e
                    );
                    continue;
                }
            };
            let hostname = parts[1].to_string();

            if let Some(old) = self.hostnames.insert(uid, hostname.clone()) {
                error!(
                    "UID Map Warning: Duplicated UID {} at line {}, overwriting '{}' with '{}'",
                    uid,
                    line_no + 1,
                    old,
                    hostname
                );
            }
        }
        Ok(())
    }

    pub fn get_host(&self, uid: u8) -> Option<String> {
        self.hostnames.get(&uid).cloned()
    }

    pub fn get_uid(&self, name: &str) -> Option<u8> {
        for (u, h) in &self.hostnames {
            if h == name {
                return Some(*u);
            }
        }
        None
    }
}
