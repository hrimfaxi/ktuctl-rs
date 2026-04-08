use std::collections::{HashMap, VecDeque};
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use clap::Parser;
use rand::RngCore;
use tokio::net::UdpSocket;
use tokio::process::Command;
use tokio::sync::Mutex;

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

#[derive(Parser, Debug, Clone)]
#[command(name = "tuctl-server")]
struct Args {
    #[arg(long, default_value = "::")]
    bind: String,

    #[arg(long, default_value_t = DEFAULT_SERVER_PORT)]
    port: u16,

    #[arg(long)]
    psk: String,

    #[arg(long, default_value_t = DEFAULT_WINDOW)]
    window: u32,

    #[arg(long = "replay-max", default_value_t = DEFAULT_REPLAY_MAX)]
    replay_max: u32,
}

fn log_info(msg: &str) {
    eprintln!("[INFO] {}", msg);
}

fn log_error(msg: &str) {
    eprintln!("[ERROR] {}", msg);
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
        Ok(v) => match v.parse::<u32>() {
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
    fn new(window: u32, max_size: u32) -> Self {
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

    fn replay_add(&mut self, ts: i64, nonce: &[u8; NONCE_LEN]) {
        self.entries.push_back(ReplayEntry { ts, nonce: *nonce });
        while self.entries.len() > self.max_size as usize {
            self.entries.pop_front();
        }
    }
}

fn detect_ktuctl() -> bool {
    if let Ok(val) = env::var("TUTUICMPTUNNEL_USE_KTUCTL") {
        if let Ok(v) = val.parse::<u32>() {
            if v != 0 {
                return true;
            }
        }
    }

    Path::new("/sys/module/tutuicmptunnel").exists()
}

fn sudo_enabled() -> bool {
    if let Ok(val) = env::var("TUTUICMPTUNNEL_DISABLE_SUDO") {
        if let Ok(v) = val.parse::<u32>() {
            if v != 0 {
                return false;
            }
        }
    }
    true
}

async fn execute_command(cmd: &[u8]) -> Result<Vec<u8>, String> {
    let sudo = sudo_enabled();

    let tuctl_prog = if detect_ktuctl() {
        log_info("Use ktuctl instead of tuctl");
        "ktuctl"
    } else {
        "tuctl"
    };

    let mut program = if sudo {
        let mut c = Command::new("sudo");
        c.arg(tuctl_prog).arg("script").arg("-");
        c
    } else {
        let mut c = Command::new(tuctl_prog);
        c.arg("script").arg("-");
        c
    };

    let mut child = program
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            if sudo {
                log_error("sudo enabled, please check sudo setting");
            }
            format!("spawn failed: {}", e)
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        use tokio::io::AsyncWriteExt;
        stdin
            .write_all(cmd)
            .await
            .map_err(|e| format!("write child stdin failed: {}", e))?;
    }

    let output = child
        .wait_with_output()
        .await
        .map_err(|e| format!("wait child failed: {}", e))?;

    let mut resp = output.stdout;
    resp.extend_from_slice(&output.stderr);

    if resp.len() > MAX_PT_SIZE {
        resp.truncate(MAX_PT_SIZE);
    }

    Ok(resp)
}

fn encrypt_packet(
    psk: &str,
    payload: &[u8],
    memlimit: usize,
) -> Result<(Vec<u8>, [u8; NONCE_LEN], i64), String> {
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

    let mut packet = Vec::with_capacity(SALT_LEN + TS_LEN + NONCE_LEN + ct.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&(ts as u64).to_be_bytes());
    packet.extend_from_slice(&nonce);
    packet.extend_from_slice(&ct);

    Ok((packet, nonce, ts))
}

fn decrypt_packet(
    psk: &str,
    pkt_in: &[u8],
    memlimit: usize,
) -> Result<(Vec<u8>, [u8; NONCE_LEN], i64), String> {
    if pkt_in.len() < MIN_LEN {
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
        .map_err(|_| "decrypt/auth fail".to_string())?;

    Ok((pt, nonce_arr, ts))
}

#[derive(Debug, Clone)]
struct Bucket {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

#[derive(Debug)]
struct AsyncRateLimiter {
    map: HashMap<IpAddr, Bucket>,
    burst_tokens: f64,
    refill_rate: f64,
    idle_evict_sec: u64,
}

impl AsyncRateLimiter {
    fn new(burst_tokens: f64, refill_rate: f64, idle_evict_sec: u64) -> Self {
        Self {
            map: HashMap::new(),
            burst_tokens,
            refill_rate,
            idle_evict_sec,
        }
    }

    fn allow(&mut self, addr: &SocketAddr) -> bool {
        let now = Instant::now();
        let ip = addr.ip();

        self.map
            .retain(|_, v| now.duration_since(v.last_seen).as_secs() <= self.idle_evict_sec);

        let entry = self.map.entry(ip).or_insert_with(|| Bucket {
            tokens: self.burst_tokens,
            last_refill: now,
            last_seen: now,
        });

        let dt = now.duration_since(entry.last_refill).as_secs_f64();
        if dt > 0.0 {
            entry.tokens += dt * self.refill_rate;
            if entry.tokens > self.burst_tokens {
                entry.tokens = self.burst_tokens;
            }
            entry.last_refill = now;
        }

        entry.last_seen = now;

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

async fn process_packet(
    socket: Arc<UdpSocket>,
    peer: SocketAddr,
    packet: Vec<u8>,
    psk: Arc<String>,
    memlimit: usize,
    replay: Arc<Mutex<ReplayWindow>>,
) {
    let (mut pt, nonce, ts) = {
        let mut rw = replay.lock().await;

        let (pt, nonce, ts) = match decrypt_packet(&psk, &packet, memlimit) {
            Ok(v) => v,
            Err(e) => {
                log_error(&format!("drop: {} from {}", e, addr_to_str(&peer)));
                return;
            }
        };

        if !rw.replay_check(ts, &nonce) {
            log_error(&format!("drop: replay/window from {}", addr_to_str(&peer)));
            return;
        }

        rw.replay_add(ts, &nonce);
        (pt, nonce, ts)
    };

    let _ = nonce;
    let _ = ts;

    remove_padding(&mut pt);

    log_info(&format!(
        "command from {} ({} bytes)",
        addr_to_str(&peer),
        pt.len()
    ));
    log_info(&format!("  {}", String::from_utf8_lossy(&pt)));

    let mut resp = match execute_command(&pt).await {
        Ok(v) => v,
        Err(e) => {
            log_error(&format!("command execution failed: {}", e));
            return;
        }
    };

    if resp.len() < MAX_PT_SIZE - 2 {
        let mut padding_len = (rand::random::<u8>() as usize) % 256;
        if resp.len() + padding_len >= MAX_PT_SIZE {
            padding_len = MAX_PT_SIZE - resp.len() - 1;
        }
        resp.extend(std::iter::repeat(b'#').take(padding_len));
    }

    if resp.len() < MAX_PT_SIZE {
        resp.push(0);
        resp.pop();
    }

    log_info(&format!("response: {} bytes", resp.len()));

    let (enc, nonce2, ts2) = match encrypt_packet(&psk, &resp, memlimit) {
        Ok(v) => v,
        Err(e) => {
            log_error(&format!("failed to encrypt response: {}", e));
            return;
        }
    };

    {
        let mut rw = replay.lock().await;
        rw.replay_add(ts2, &nonce2);
    }

    if let Err(e) = socket.send_to(&enc, peer).await {
        log_error(&format!("failed to send response: {}", e));
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if args.psk.len() < 8 {
        log_error("PSK must be at least 8 characters long");
        std::process::exit(2);
    }

    let memlimit = setup_pwhash_memlimit();

    let bind_addr = format!("{}:{}", args.bind, args.port);
    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);

    let local = socket.local_addr()?;
    log_info(&format!(
        "Server listen {}, replay window = {}s, max={}",
        addr_to_str(&local),
        args.window,
        args.replay_max
    ));

    let replay = Arc::new(Mutex::new(ReplayWindow::new(args.window, args.replay_max)));
    let rate_limiter = Arc::new(Mutex::new(AsyncRateLimiter::new(10.0, 5.0, 60)));
    let psk = Arc::new(args.psk);

    loop {
        let mut buf = vec![0u8; MAX_CT_SIZE];
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                log_error(&format!("recvfrom error: {}", e));
                continue;
            }
        };
        buf.truncate(len);

        {
            let mut rl = rate_limiter.lock().await;
            if !rl.allow(&peer) {
                log_info(&format!(
                    "too many requests from {}, dropping",
                    addr_to_str(&peer)
                ));
                continue;
            }
        }

        let sock = Arc::clone(&socket);
        let psk = Arc::clone(&psk);
        let replay = Arc::clone(&replay);

        tokio::spawn(async move {
            process_packet(sock, peer, buf, psk, memlimit, replay).await;
        });
    }
}
