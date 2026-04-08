use zerocopy::{FromBytes, Immutable, IntoBytes};

// --- Constants
pub const PROJECT_NAME: &str = "ktuctl-rs";
pub const TUTU_GENL_FAMILY_NAME: &str = "tutuicmptunnel";
pub const TUTU_GENL_VERSION: u8 = 0x1;
pub const UID_CONFIG_PATH: &str = "/etc/tutuicmptunnel/uids";

// Custom Attribute IDs
pub const TUTU_ATTR_CONFIG: u16 = 1;
pub const TUTU_ATTR_STATS: u16 = 2;
pub const TUTU_ATTR_EGRESS: u16 = 3;
pub const TUTU_ATTR_INGRESS: u16 = 4;
pub const TUTU_ATTR_SESSION: u16 = 5;
pub const TUTU_ATTR_USER_INFO: u16 = 6;
pub const TUTU_ATTR_IFNAME_NAME: u16 = 7;

// Commands
pub const TUTU_CMD_GET_CONFIG: u8 = 1;
pub const TUTU_CMD_SET_CONFIG: u8 = 2;
pub const TUTU_CMD_GET_STATS: u8 = 3;
pub const TUTU_CMD_GET_EGRESS: u8 = 5;
pub const TUTU_CMD_DELETE_EGRESS: u8 = 6;
pub const TUTU_CMD_UPDATE_EGRESS: u8 = 7;
pub const TUTU_CMD_GET_INGRESS: u8 = 8;
pub const TUTU_CMD_DELETE_INGRESS: u8 = 9;
pub const TUTU_CMD_UPDATE_INGRESS: u8 = 10;
pub const TUTU_CMD_GET_SESSION: u8 = 11;
pub const TUTU_CMD_GET_USER_INFO: u8 = 14;
pub const TUTU_CMD_DELETE_USER_INFO: u8 = 15;
pub const TUTU_CMD_UPDATE_USER_INFO: u8 = 16;
pub const TUTU_CMD_IFNAME_GET: u8 = 17;
pub const TUTU_CMD_IFNAME_ADD: u8 = 18;
pub const TUTU_CMD_IFNAME_DEL: u8 = 19;

// Flags
pub const TUTU_ANY: u64 = 0;
pub const TUTU_NOEXIST: u64 = 1;

// netlink / genetlink constants
pub const NLMSG_ALIGNTO: usize = 4;
pub const NLA_ALIGNTO: usize = 4;
pub const GENL_ID_CTRL: u16 = 0x10;
pub const CTRL_CMD_GETFAMILY: u8 = 3;
pub const CTRL_ATTR_FAMILY_ID: u16 = 1;
pub const CTRL_ATTR_FAMILY_NAME: u16 = 2;

pub const NLM_F_REQUEST: u16 = 0x0001;
pub const NLM_F_ACK: u16 = 0x0004;
pub const NLM_F_DUMP: u16 = 0x0300;

pub const NLMSG_ERROR: u16 = 0x2;
pub const NLMSG_DONE: u16 = 0x3;

// --- Protocol Structs ---

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuConfig {
    pub session_max_age: u32,
    pub _pad0: u8,
    pub is_server: u8,
    pub _pad1: [u8; 2],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuStats {
    pub packets_processed: u64,
    pub packets_dropped: u64,
    pub checksum_errors: u64,
    pub fragmented: u64,
    pub gso: u64,
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct UserInfoValue {
    pub address: In6Addr,
    pub icmp_id: u16, // BE
    pub dport: u16,   // BE
    pub comment: [u8; 22],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuUserInfo {
    pub uid: u8,
    pub _pad0: [u8; 3],
    pub value: UserInfoValue,
    pub _pad1: [u8; 2],
    pub map_flags: u64,
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct EgressPeerKey {
    pub address: In6Addr,
    pub port: u16, // BE
    pub _pad0: [u8; 2],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct EgressPeerValue {
    pub uid: u8,
    pub comment: [u8; 22],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuEgress {
    pub key: EgressPeerKey,
    pub value: EgressPeerValue,
    pub _pad0: [u8; 5],
    pub map_flags: u64,
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct IngressPeerKey {
    pub address: In6Addr,
    pub uid: u8,
    pub _pad0: [u8; 3],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct IngressPeerValue {
    pub port: u16, // BE
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuIngress {
    pub key: IngressPeerKey,
    pub value: IngressPeerValue,
    pub _pad0: [u8; 2],
    pub map_flags: u64,
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct SessionKey {
    pub address: In6Addr,
    pub sport: u16, // BE
    pub dport: u16, // BE
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct SessionValue {
    pub age: u64,
    pub uid: u8,
    pub _pad0: u8,
    pub client_sport: u16, // BE
    pub _pad_end: [u8; 4],
}

#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable)]
#[repr(C)]
pub struct TutuSession {
    pub key: SessionKey,
    pub _pad0: [u8; 4],
    pub value: SessionValue,
    pub _pad1: [u8; 8],
    pub map_flags: u64,
}

pub type In6Addr = [u8; 16];
