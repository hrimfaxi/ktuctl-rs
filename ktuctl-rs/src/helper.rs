use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, Ipv6Addr};
use std::sync::RwLock;

use crate::config::*;
use crate::uid_map::*;

#[derive(Default)]
pub struct GlobalFlags {
    pub numeric: bool,
    pub debug: bool,
    pub ip_family: Option<String>,
}

// --- Global State ---
lazy_static::lazy_static! {
    pub static ref UID_MAP: RwLock<UidMap> = RwLock::new(UidMap::new());
    pub static ref GLOBAL_FLAGS: RwLock<GlobalFlags> = RwLock::new(GlobalFlags::default());
}

// --- Helpers ---
pub fn htons(v: u16) -> u16 {
    v.to_be()
}

pub fn ntohs(v: u16) -> u16 {
    u16::from_be(v)
}

pub fn resolve_uid(s: &str) -> Result<u8> {
    if let Ok(uid_map) = UID_MAP.read() {
        if let Some(uid) = uid_map.get_uid(s) {
            return Ok(uid);
        }
    }
    s.parse::<u8>()
        .map_err(|_| anyhow!("unknown user or invalid uid format: {}", s))
}

pub fn resolve_hostname(uid: u8, is_dump: bool) -> String {
    let numeric = GLOBAL_FLAGS.read().expect("rwlock poisoned").numeric;
    if numeric {
        if is_dump {
            return format!("uid {}", uid);
        }
        return format!("UID: {}", uid);
    }

    if let Ok(uid_map) = UID_MAP.read() {
        if let Some(name) = uid_map.get_host(uid) {
            if is_dump {
                return format!("user {}", name);
            }
            return format!("User: {}", name);
        }
    }

    if is_dump {
        format!("uid {}", uid)
    } else {
        format!("UID: {}", uid)
    }
}

pub fn resolve_ip(addr: &str) -> Result<In6Addr> {
    let family = GLOBAL_FLAGS
        .read()
        .expect("rwlock poisoned")
        .ip_family
        .clone();
    let ips: Vec<IpAddr> = dns_lookup::lookup_host(addr)?.collect();

    if ips.is_empty() {
        bail!("could not resolve address: {}", addr);
    }

    let ip = match family.as_deref() {
        Some("ip4") => ips.iter().find(|i: &&IpAddr| i.is_ipv4()).copied(),
        Some("ip6") => ips.iter().find(|i: &&IpAddr| i.is_ipv6()).copied(),
        _ => Some(ips[0]),
    }
    .ok_or_else(|| anyhow!("no suitable address found"))?;

    let mut res = [0u8; 16];
    match ip {
        IpAddr::V4(v4) => {
            res[10] = 0xff;
            res[11] = 0xff;
            res[12..16].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            res.copy_from_slice(&v6.octets());
        }
    }
    Ok(res)
}

pub fn ip_to_string(addr: &In6Addr) -> String {
    let ip = Ipv6Addr::from(*addr);
    if let Some(v4) = ip.to_ipv4() {
        return v4.to_string();
    }
    ip.to_string()
}

pub fn format_comment(c: &[u8; 22], is_dump: bool) -> String {
    let len = c.iter().position(|&x| x == 0).unwrap_or(c.len());
    let s = String::from_utf8_lossy(&c[..len]);
    if s.is_empty() {
        return String::new();
    }
    if is_dump {
        format!(" comment {}", s)
    } else {
        format!(", Comment: {}", s)
    }
}

pub fn copy_comment(dest: &mut [u8; 22], src: &str) {
    *dest = [0; 22];
    let bytes = src.as_bytes();
    let len = bytes.len().min(22);
    dest[..len].copy_from_slice(&bytes[..len]);
}
