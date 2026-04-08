use std::collections::VecDeque;
use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io::{self, Read};
use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs, UdpSocket};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;

const DEFAULT_SERVER: &str = "127.0.0.1";
const DEFAULT_SERVER_PORT: u16 = 7000;
const DEFAULT_WINDOW: u32 = 30;
const DEFAULT_REPLAY_MAX: u32 = 1024;

const SALT_LEN: usize = 16;
const TS_LEN: usize = 8;
const NONCE_LEN: usize = 24;
const KEYB: usize = 32;
const TAG: usize = 16;

const MAX_PT_SIZE: usize = 4096;
const MAX_CT_SIZE: usize = SALT_LEN + TS_LEN + NONCE_LEN + MAX_PT_SIZE + TAG;
const MIN_LEN: usize = SALT_LEN + TS_LEN + NONCE_LEN + TAG;

#[derive(Debug, Clone)]
struct Args {
    script: String,
    psk: String,
    server: String,
    server_port: u16,
    family: Family,
    window: u32,
    max_retries: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Family {
    Unspec,
    Inet4,
    Inet6,
}

fn print_client_usage(argv0: &str) -> i32 {
    eprintln!(
        "Usage: {} psk PSK [script SCRIPT|-] [server SERVER] [server-port SERVER_PORT] [window WINDOW] [max-retries MAX_RETRIES] [-4] [-6]",
        argv0
    );
    0
}

fn log_info(msg: &str) {
    eprintln!("[INFO] {}", msg);
}

fn log_error(msg: &str) {
    eprintln!("[ERROR] {}", msg);
}

fn matches(tok: &str, kw: &str) -> bool {
    tok == kw
}

fn is_help_kw(tok: &str) -> bool {
    matches!(tok, "-h" | "--help" | "help")
}

fn parse_u16(s: &str) -> Result<u16, String> {
    s.parse::<u16>()
        .map_err(|e| format!("invalid u16 '{}': {}", s, e))
}

fn parse_u32(s: &str) -> Result<u32, String> {
    s.parse::<u32>()
        .map_err(|e| format!("invalid u32 '{}': {}", s, e))
}

fn parse_port(s: &str) -> Result<u16, String> {
    let p = parse_u16(s)?;
    if p == 0 {
        return Err("port must be non-zero".into());
    }
    Ok(p)
}

fn parse_window(s: &str) -> Result<u32, String> {
    let w = parse_u32(s)?;
    if w == 0 {
        return Err("window must be > 0".into());
    }
    Ok(w)
}

fn read_script(path: &str) -> Result<String, String> {
    if path == "-" {
        let mut s = String::new();
        io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| format!("read stdin failed: {}", e))?;
        return Ok(s);
    }
    fs::read_to_string(path).map_err(|e| format!("read_script '{}' failed: {}", path, e))
}

fn parse_dsl_args(argc: usize, argv: &[String]) -> Result<Args, i32> {
    let mut psk: Option<String> = None;
    let mut server = DEFAULT_SERVER.to_string();
    let mut server_port = DEFAULT_SERVER_PORT;
    let mut script = "-".to_string();
    let mut family = Family::Unspec;
    let mut max_retries = 3u16;
    let mut window = DEFAULT_WINDOW;

    let mut i = 1usize;
    while i < argc {
        let tok = &argv[i];

        if matches(tok, "server-port") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            match parse_port(&argv[i]) {
                Ok(v) => server_port = v,
                Err(e) => {
                    log_error(&e);
                    let _ = print_client_usage(&argv[0]);
                    return Err(-22);
                }
            }
        } else if matches(tok, "script") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            script = argv[i].clone();
        } else if matches(tok, "psk") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            psk = Some(argv[i].clone());
        } else if matches(tok, "server") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            server = argv[i].clone();
        } else if matches(tok, "window") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            match parse_window(&argv[i]) {
                Ok(v) => window = v,
                Err(e) => {
                    log_error(&e);
                    let _ = print_client_usage(&argv[0]);
                    return Err(-22);
                }
            }
        } else if matches(tok, "max-retries") {
            i += 1;
            if i >= argc {
                let _ = print_client_usage(&argv[0]);
                return Err(-22);
            }
            match parse_u16(&argv[i]) {
                Ok(v) => max_retries = v,
                Err(e) => {
                    log_error(&e);
                    let _ = print_client_usage(&argv[0]);
                    return Err(-22);
                }
            }
        } else if matches(tok, "-4") {
            family = Family::Inet4;
        } else if matches(tok, "-6") {
            family = Family::Inet6;
        } else if is_help_kw(tok) {
            let _ = print_client_usage(&argv[0]);
            return Err(-22);
        } else {
            log_error(&format!("unknown keyword \"{}\"", tok));
            let _ = print_client_usage(&argv[0]);
            return Err(-22);
        }

        i += 1;
    }

    let psk = match psk {
        Some(v) => v,
        None => {
            log_error("psk must be specified");
            let _ = print_client_usage(&argv[0]);
            return Err(-22);
        }
    };

    if psk.len() < 8 {
        log_error("PSK must be at least 8 characters long");
        let _ = print_client_usage(&argv[0]);
        return Err(-22);
    }

    let content = match read_script(&script) {
        Ok(s) => s,
        Err(e) => {
            log_error(&e);
            return Err(-1);
        }
    };

    Ok(Args {
        script: content,
        psk,
        server,
        server_port,
        family,
        window,
        max_retries,
    })
}

fn current_unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs() as i64
}

fn addr_to_str(addr: &SocketAddr) -> String {
    match addr {
        SocketAddr::V4(v4) => format!("[{}]:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    }
}

fn setup_pwhash_memlimit() -> usize {
    let default_mem = 64 * 1024 * 1024usize;
    match env::var("TUTUICMPTUNNEL_PWHASH_MEMLIMIT") {
        Ok(v) => match parse_u32(&v) {
            Ok(out) => {
                let m = out as usize;
                log_info(&format!("pwhash memory limit set to {}", m));
                m
            }
            Err(_) => {
                log_error(&format!("invalid pwhash memory limit value: {}", v));
                default_mem
            }
        },
        Err(_) => default_mem,
    }
}

fn psk2key(psk: &str, salt: &[u8], memlimit: usize) -> Result<[u8; KEYB], String> {
    if salt.len() != SALT_LEN {
        return Err("invalid salt length".into());
    }

    let mut key = [0u8; KEYB];
    let params = Params::new((memlimit / 1024) as u32, 2, 1, Some(KEYB))
        .map_err(|e| format!("argon2 params failed: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(psk.as_bytes(), salt, &mut key)
        .map_err(|e| format!("derive key failed: {}", e))?;

    Ok(key)
}

fn remove_padding(pt: &mut Vec<u8>) {
    if pt.is_empty() {
        return;
    }
    while pt.last().copied() == Some(b'#') {
        pt.pop();
    }
}

#[derive(Debug, Clone)]
struct ReplayEntry {
    ts: i64,
    nonce: [u8; NONCE_LEN],
}

#[derive(Debug)]
struct ReplayWindow {
    window: u32,
    max_size: u32,
    entries: VecDeque<ReplayEntry>,
}

impl ReplayWindow {
    fn init(window: u32, max_size: u32) -> Self {
        Self {
            window,
            max_size,
            entries: VecDeque::new(),
        }
    }

    fn replay_check(&mut self, ts: i64, nonce: &[u8; NONCE_LEN]) -> bool {
        let now = current_unix_time();

        if (now - ts).abs() > self.window as i64 {
            return false;
        }

        self.entries.retain(|e| e.ts + self.window as i64 >= now);

        for e in &self.entries {
            if e.ts == ts && &e.nonce == nonce {
                return false;
            }
        }

        true
    }

    fn replay_add(&mut self, ts: i64, nonce: &[u8; NONCE_LEN]) -> Result<(), String> {
        self.entries.push_back(ReplayEntry { ts, nonce: *nonce });
        while self.entries.len() > self.max_size as usize {
            self.entries.pop_front();
        }
        Ok(())
    }
}

fn resolve_ip_addr(family: Family, server: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = IpAddr::from_str(server) {
        return match (family, ip) {
            (Family::Inet4, IpAddr::V4(_)) => Ok(ip),
            (Family::Inet6, IpAddr::V6(_)) => Ok(ip),
            (Family::Unspec, _) => Ok(ip),
            _ => Err(format!("address family mismatch: {}", server)),
        };
    }

    let addrs = (server, 0u16)
        .to_socket_addrs()
        .map_err(|e| format!("resolve_ip_addr failed for '{}': {}", server, e))?;

    for sa in addrs {
        match (family, sa.ip()) {
            (Family::Inet4, IpAddr::V4(v4)) => return Ok(IpAddr::V4(v4)),
            (Family::Inet6, IpAddr::V6(v6)) => return Ok(IpAddr::V6(v6)),
            (Family::Unspec, ip) => return Ok(ip),
            _ => {}
        }
    }

    Err(format!("no suitable address found for '{}'", server))
}

fn encrypt_and_send_packet(
    sock: &UdpSocket,
    cli: SocketAddr,
    rwin: &mut ReplayWindow,
    psk: &str,
    payload: &[u8],
    out_packet_len: Option<&mut usize>,
    memlimit: usize,
) -> Result<(), String> {
    let ts = current_unix_time();

    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);

    let key_bytes = psk2key(psk, &salt, memlimit)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let mut aad = Vec::with_capacity(SALT_LEN + TS_LEN);
    aad.extend_from_slice(&salt);
    aad.extend_from_slice(&(ts as u64).to_be_bytes());

    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|e| format!("encryption failed: {}", e))?;

    let packet_len = SALT_LEN + TS_LEN + NONCE_LEN + ct.len();
    let mut packet = Vec::with_capacity(packet_len);
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&(ts as u64).to_be_bytes());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ct);

    sock.send_to(&packet, cli)
        .map_err(|e| format!("sendto: {}", e))?;

    rwin.replay_add(ts, &nonce)?;

    if let Some(out) = out_packet_len {
        *out = packet_len;
    }

    Ok(())
}

fn decrypt_and_validate_packet(
    pkt_in: &[u8],
    rwin: &mut ReplayWindow,
    psk: &str,
    cli: SocketAddr,
    memlimit: usize,
) -> Result<Vec<u8>, String> {
    if pkt_in.len() < MIN_LEN {
        log_error(&format!("drop: short packet from {}", addr_to_str(&cli)));
        return Err("short packet".into());
    }

    let salt = &pkt_in[0..SALT_LEN];
    let ts_b = &pkt_in[SALT_LEN..SALT_LEN + TS_LEN];
    let nonce = &pkt_in[SALT_LEN + TS_LEN..SALT_LEN + TS_LEN + NONCE_LEN];
    let ct = &pkt_in[SALT_LEN + TS_LEN + NONCE_LEN..];

    let mut ts_arr = [0u8; 8];
    ts_arr.copy_from_slice(ts_b);
    let ts = u64::from_be_bytes(ts_arr) as i64;

    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);

    if !rwin.replay_check(ts, &nonce_arr) {
        log_error(&format!("drop: replay/window from {}", addr_to_str(&cli)));
        return Err("replay/window".into());
    }

    let key_bytes = psk2key(psk, salt, memlimit)?;
    let cipher = XChaCha20Poly1305::new(Key::from_slice(&key_bytes));

    let mut aad = Vec::with_capacity(SALT_LEN + TS_LEN);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(ts_b);

    let pt = cipher
        .decrypt(
            XNonce::from_slice(&nonce_arr),
            Payload { msg: ct, aad: &aad },
        )
        .map_err(|_| {
            log_error(&format!(
                "drop: decrypt/auth fail from {}",
                addr_to_str(&cli)
            ));
            "decrypt/auth fail".to_string()
        })?;

    rwin.replay_add(ts, &nonce_arr)?;
    Ok(pt)
}

fn set_sock_timeout(sock: &UdpSocket, timeout_sec: u64) -> Result<(), String> {
    sock.set_read_timeout(Some(Duration::from_secs(timeout_sec)))
        .map_err(|e| format!("set_read_timeout: {}", e))
}

fn build_padded_cmd(script: &str) -> Vec<u8> {
    let mut cmd = script.as_bytes().to_vec();

    let mut pad_len = 0usize;
    if MAX_PT_SIZE > 0 {
        pad_len = (rand::random::<u8>() as usize) % 256;
    }

    if cmd.len() + pad_len > MAX_PT_SIZE.saturating_sub(1) {
        pad_len = MAX_PT_SIZE.saturating_sub(1).saturating_sub(cmd.len());
    }

    cmd.extend(std::iter::repeat(b'#').take(pad_len));
    cmd
}

fn create_dualstack_udp_socket() -> Result<UdpSocket, String> {
    let sock = UdpSocket::bind(SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))
    .map_err(|e| format!("socket bind failed: {}", e))?;

    Ok(sock)
}

fn run() -> Result<(), i32> {
    let argv: Vec<String> = env::args().collect();
    let argc = argv.len();

    let memlimit = setup_pwhash_memlimit();
    let a = parse_dsl_args(argc, &argv)?;

    let mut rwin = ReplayWindow::init(a.window, DEFAULT_REPLAY_MAX);

    let timeout = 5u64;
    let mut retries = 0u16;

    'retry: loop {
        let cmd = build_padded_cmd(&a.script);

        let sock = match create_dualstack_udp_socket() {
            Ok(s) => s,
            Err(e) => {
                log_error(&e);
                return Err(-1);
            }
        };

        let ip = match resolve_ip_addr(a.family, &a.server) {
            Ok(ip) => ip,
            Err(e) => {
                log_error(&e);
                return Err(-1);
            }
        };

        let dst = SocketAddr::new(ip, a.server_port);

        let mut packet_len = 0usize;
        if let Err(e) = encrypt_and_send_packet(
            &sock,
            dst,
            &mut rwin,
            &a.psk,
            &cmd,
            Some(&mut packet_len),
            memlimit,
        ) {
            log_error(&e);
            return Err(-1);
        }

        log_info(&format!(
            "sent {} bytes to {}:{}",
            packet_len, a.server, a.server_port
        ));

        if let Err(e) = set_sock_timeout(&sock, timeout) {
            log_error(&e);
            return Err(-1);
        }

        let mut buf = [0u8; MAX_CT_SIZE];
        let (len, cli) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut {
                    log_error("recvfrom timeout");
                    if retries < a.max_retries {
                        retries += 1;
                        std::thread::sleep(Duration::from_millis(100));
                        log_info(&format!(
                            "performing retries: {} / {}",
                            retries, a.max_retries
                        ));
                        continue 'retry;
                    }
                } else {
                    log_error(&format!("recvfrom error: {}", e));
                }
                return Err(-1);
            }
        };

        if len < MIN_LEN {
            log_error(&format!("drop: short packet from {}", addr_to_str(&cli)));
            return Err(-22);
        }

        let mut pt =
            match decrypt_and_validate_packet(&buf[..len], &mut rwin, &a.psk, cli, memlimit) {
                Ok(pt) => pt,
                Err(e) => {
                    log_error(&e);
                    return Err(-1);
                }
            };

        remove_padding(&mut pt);

        let mut s = String::new();
        let _ = write!(&mut s, "{}", String::from_utf8_lossy(&pt));
        log_info(&format!("response from {}: {}", addr_to_str(&cli), s));
        break;
    }

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::from(0),
        Err(code) => {
            let c = if code < 0 { 1 } else { code as u8 };
            ExitCode::from(c)
        }
    }
}
