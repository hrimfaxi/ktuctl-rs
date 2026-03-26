use crate::config::*;
use crate::helper::*;
use crate::netlink::*;

use anyhow::{anyhow, bail, Context, Result};
use log::{error, info};

use std::fs::File;
use std::io::{BufRead, BufReader};

// --- Commands ---
pub fn cmd_load(args: &[String]) -> Result<()> {
    let print_list = || -> Result<()> {
        println!("Managed interfaces:");
        let mut found = false;
        dump_strings(TUTU_CMD_IFNAME_GET, TUTU_ATTR_IFNAME_NAME, |s| {
            println!("  {}", s);
            found = true;
            Ok(())
        })?;
        if !found {
            println!("  [all interfaces]");
        }
        println!();
        Ok(())
    };

    if args.is_empty() {
        return print_list();
    }

    let mut i = 0;
    while i < args.len() {
        if args[i] == "iface" && i + 1 < args.len() {
            let ifname = &args[i + 1];
            send_string(TUTU_CMD_IFNAME_ADD, TUTU_ATTR_IFNAME_NAME, ifname, true)
                .with_context(|| format!("failed to add interface {}", ifname))?;
            println!("Adding interface: {}", ifname);
            i += 1;
        }
        i += 1;
    }
    print_list()
}

pub fn cmd_unload(args: &[String]) -> Result<()> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == "iface" && i + 1 < args.len() {
            let ifname = &args[i + 1];
            match send_string(TUTU_CMD_IFNAME_DEL, TUTU_ATTR_IFNAME_NAME, ifname, true) {
                Ok(_) => println!("Removing interface: {}", ifname),
                Err(e) => {
                    println!(
                        "Error removing {}: {} (Interface may not be in list)",
                        ifname, e
                    );
                }
            }
            i += 1;
        }
        i += 1;
    }

    println!("Managed interfaces:");
    let mut found = false;
    dump_strings(TUTU_CMD_IFNAME_GET, TUTU_ATTR_IFNAME_NAME, |s| {
        println!("  {}", s);
        found = true;
        Ok(())
    })?;
    if !found {
        println!("  [all interfaces]");
    }
    Ok(())
}

pub fn cmd_server(args: &[String]) -> Result<()> {
    let mut max_age = 60u32;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "max-age" && i + 1 < args.len() {
            max_age = args[i + 1].parse()?;
            i += 1;
        }
        i += 1;
    }
    info!("server mode, session max age={}", max_age);
    let cfg = TutuConfig {
        session_max_age: max_age,
        is_server: 1,
        _pad0: 0,
        _pad1: [0; 2],
    };
    send_struct(TUTU_CMD_SET_CONFIG, TUTU_ATTR_CONFIG, &cfg, true)
}

pub fn cmd_client(_args: &[String]) -> Result<()> {
    println!("client mode");
    let cfg = TutuConfig {
        session_max_age: 0,
        is_server: 0,
        _pad0: 0,
        _pad1: [0; 2],
    };
    send_struct(TUTU_CMD_SET_CONFIG, TUTU_ATTR_CONFIG, &cfg, true)
}

pub fn cmd_client_add(args: &[String]) -> Result<()> {
    let mut address = String::new();
    let mut port = 0u16;
    let mut uid = 0u8;
    let mut comment = String::new();
    let mut uid_set = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "address" | "addr" => {
                if i + 1 >= args.len() {
                    bail!("missing value for address");
                }
                address = args[i + 1].clone();
                i += 1;
            }
            "port" => {
                if i + 1 >= args.len() {
                    bail!("missing value for port");
                }
                port = args[i + 1].parse()?;
                i += 1;
            }
            "uid" | "user" => {
                if i + 1 >= args.len() {
                    bail!("missing value for uid");
                }
                uid = resolve_uid(&args[i + 1])?;
                uid_set = true;
                i += 1;
            }
            "comment" => {
                if i + 1 >= args.len() {
                    bail!("missing value for comment");
                }
                comment = args[i + 1].clone();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if address.is_empty() || port == 0 || !uid_set {
        bail!("UID, address, and port must be specified");
    }

    let cfg: TutuConfig = receive_struct(TUTU_CMD_GET_CONFIG, TUTU_ATTR_CONFIG, None)?;
    if cfg.is_server != 0 {
        bail!("must be in client mode");
    }

    let in6 = resolve_ip(&address)?;

    let mut egress = TutuEgress {
        key: EgressPeerKey {
            address: in6,
            port: htons(port),
            _pad0: [0; 2],
        },
        value: EgressPeerValue {
            uid,
            comment: [0; 22],
        },
        _pad0: [0; 5],
        map_flags: TUTU_ANY,
    };
    copy_comment(&mut egress.value.comment, &comment);

    let ingress = TutuIngress {
        key: IngressPeerKey {
            address: in6,
            uid,
            _pad0: [0; 3],
        },
        value: IngressPeerValue { port: htons(port) },
        _pad0: [0; 2],
        map_flags: TUTU_NOEXIST,
    };

    match send_struct(TUTU_CMD_UPDATE_INGRESS, TUTU_ATTR_INGRESS, &ingress, true) {
        Ok(_) => {}
        Err(e) => {
            bail!("ingress update failed (possible port conflict): {}", e);
        }
    }

    send_struct(TUTU_CMD_UPDATE_EGRESS, TUTU_ATTR_EGRESS, &egress, true)?;

    info!(
        "client set: {}, address: {}, port: {}, comment: {}",
        resolve_hostname(uid, false),
        ip_to_string(&in6),
        port,
        comment
    );
    Ok(())
}

pub fn cmd_client_del(args: &[String]) -> Result<()> {
    let mut address = String::new();
    let mut uid = 0u8;
    let mut uid_set = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "address" | "addr" => {
                if i + 1 >= args.len() {
                    bail!("missing value for address");
                }
                address = args[i + 1].clone();
                i += 1;
            }
            "uid" | "user" => {
                if i + 1 >= args.len() {
                    bail!("missing value for uid");
                }
                uid = resolve_uid(&args[i + 1])?;
                uid_set = true;
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if address.is_empty() || !uid_set {
        bail!("UID and address must be specified");
    }
    let in6 = resolve_ip(&address)?;

    let mut deleted = false;

    let mut egress_todel: Option<TutuEgress> = None;
    dump_structs(TUTU_CMD_GET_EGRESS, TUTU_ATTR_EGRESS, |e: &TutuEgress| {
        if e.value.uid == uid && e.key.address == in6 {
            egress_todel = Some(*e);
        }
        Ok(())
    })?;

    if let Some(e) = egress_todel {
        send_struct(TUTU_CMD_DELETE_EGRESS, TUTU_ATTR_EGRESS, &e, true)?;
        deleted = true;
    }

    let ingress_req = TutuIngress {
        key: IngressPeerKey {
            address: in6,
            uid,
            _pad0: [0; 3],
        },
        value: IngressPeerValue { port: 0 },
        _pad0: [0; 2],
        map_flags: 0,
    };

    if send_struct(
        TUTU_CMD_DELETE_INGRESS,
        TUTU_ATTR_INGRESS,
        &ingress_req,
        true,
    )
    .is_ok()
    {
        deleted = true;
    }

    if deleted {
        info!("client deleted: {}", resolve_hostname(uid, false));
    } else {
        error!("client peer not found");
    }
    Ok(())
}

pub fn cmd_server_add(args: &[String]) -> Result<()> {
    let mut address = String::new();
    let mut port = 0u16;
    let mut icmp_id = 0u16;
    let mut uid = 0u8;
    let mut comment = String::new();
    let mut uid_set = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "address" | "addr" => {
                if i + 1 >= args.len() {
                    bail!("missing value for address");
                }
                address = args[i + 1].clone();
                i += 1;
            }
            "port" => {
                if i + 1 >= args.len() {
                    bail!("missing value for port");
                }
                port = args[i + 1].parse()?;
                i += 1;
            }
            "icmp-id" => {
                if i + 1 >= args.len() {
                    bail!("missing value for icmp-id");
                }
                icmp_id = args[i + 1].parse()?;
                i += 1;
            }
            "uid" | "user" => {
                if i + 1 >= args.len() {
                    bail!("missing value for uid");
                }
                uid = resolve_uid(&args[i + 1])?;
                uid_set = true;
                i += 1;
            }
            "comment" => {
                if i + 1 >= args.len() {
                    bail!("missing value for comment");
                }
                comment = args[i + 1].clone();
                i += 1;
            }
            _ => {}
        }
        i += 1;
    }

    if !uid_set || address.is_empty() || port == 0 {
        bail!("uid, address and port must be specified");
    }

    let cfg: TutuConfig = receive_struct(TUTU_CMD_GET_CONFIG, TUTU_ATTR_CONFIG, None)?;
    if cfg.is_server == 0 {
        bail!("must be in server mode");
    }

    let in6 = resolve_ip(&address)?;

    let mut user_info = TutuUserInfo {
        uid,
        _pad0: [0; 3],
        value: UserInfoValue {
            address: in6,
            icmp_id: htons(icmp_id),
            dport: htons(port),
            comment: [0; 22],
        },
        _pad1: [0; 2],
        map_flags: TUTU_ANY,
    };
    copy_comment(&mut user_info.value.comment, &comment);

    send_struct(
        TUTU_CMD_UPDATE_USER_INFO,
        TUTU_ATTR_USER_INFO,
        &user_info,
        true,
    )?;
    info!(
        "server updated: {}, address: {}, dport: {}, comment: {}",
        resolve_hostname(uid, false),
        ip_to_string(&in6),
        port,
        comment
    );
    Ok(())
}

pub fn cmd_server_del(args: &[String]) -> Result<()> {
    let mut uid = 0u8;
    let mut uid_set = false;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "uid" || args[i] == "user" {
            if i + 1 >= args.len() {
                bail!("missing value for uid");
            }
            uid = resolve_uid(&args[i + 1])?;
            uid_set = true;
            i += 1;
        }
        i += 1;
    }

    if !uid_set {
        bail!("UID must be specified");
    }

    let del_req = TutuUserInfo {
        uid,
        _pad0: [0; 3],
        value: UserInfoValue {
            address: [0; 16],
            icmp_id: 0,
            dport: 0,
            comment: [0; 22],
        },
        _pad1: [0; 2],
        map_flags: 0,
    };

    send_struct(
        TUTU_CMD_DELETE_USER_INFO,
        TUTU_ATTR_USER_INFO,
        &del_req,
        true,
    )?;
    info!("server deleted: {}", resolve_hostname(uid, false));
    Ok(())
}

pub fn cmd_status(_args: &[String]) -> Result<()> {
    let cfg: TutuConfig = receive_struct(TUTU_CMD_GET_CONFIG, TUTU_ATTR_CONFIG, None)?;

    let role = if cfg.is_server != 0 {
        "Server"
    } else {
        "Client"
    };
    println!("{}: Role: {}\n", PROJECT_NAME, role);

    cmd_load(&[])?;

    let debug = GLOBAL_FLAGS.read().expect("rwlock poisoned").debug;

    if cfg.is_server != 0 {
        println!("Peers:");
        dump_structs(
            TUTU_CMD_GET_USER_INFO,
            TUTU_ATTR_USER_INFO,
            |u: &TutuUserInfo| {
                println!(
                    "  {}, Address: {}, Dport: {}, ICMP: {}{}",
                    resolve_hostname(u.uid, false),
                    ip_to_string(&u.value.address),
                    ntohs(u.value.dport),
                    ntohs(u.value.icmp_id),
                    format_comment(&u.value.comment, false)
                );
                Ok(())
            },
        )?;

        if debug {
            println!("\nSessions (max age: {}):", cfg.session_max_age);
            dump_structs(
                TUTU_CMD_GET_SESSION,
                TUTU_ATTR_SESSION,
                |s: &TutuSession| {
                    println!(
                        "  Address: {}, SPort: {}, DPort: {} => {}, Age: {}, Client Sport: {}",
                        ip_to_string(&s.key.address),
                        ntohs(s.key.sport),
                        ntohs(s.key.dport),
                        resolve_hostname(s.value.uid, false),
                        s.value.age,
                        ntohs(s.value.client_sport)
                    );
                    Ok(())
                },
            )?;
        }
    } else {
        println!("Client Peers:");
        let mut cnt = 0;
        dump_structs(TUTU_CMD_GET_EGRESS, TUTU_ATTR_EGRESS, |e: &TutuEgress| {
            if ntohs(e.key.port) != 0 {
                println!(
                    "  {}, Address: {}, Port: {}{}",
                    resolve_hostname(e.value.uid, false),
                    ip_to_string(&e.key.address),
                    ntohs(e.key.port),
                    format_comment(&e.value.comment, false)
                );
                cnt += 1;
            }
            Ok(())
        })?;
        if cnt == 0 {
            println!("No peer configure");
        }

        if debug {
            println!("\nIngress peers:");
            dump_structs(
                TUTU_CMD_GET_INGRESS,
                TUTU_ATTR_INGRESS,
                |in_: &TutuIngress| {
                    println!(
                        "  {}, Address: {} => Sport: {}",
                        resolve_hostname(in_.key.uid, false),
                        ip_to_string(&in_.key.address),
                        ntohs(in_.value.port)
                    );
                    Ok(())
                },
            )?;
        }
    }

    if debug {
        if let Ok(stats) = receive_struct::<TutuStats>(TUTU_CMD_GET_STATS, TUTU_ATTR_STATS, None) {
            println!("\nPackets:");
            println!("  processed:   {}", stats.packets_processed);
            println!("  dropped:     {}", stats.packets_dropped);
            println!("  cksum error: {}", stats.checksum_errors);
            println!("  fragmented:  {}", stats.fragmented);
            println!("  GSO:         {}", stats.gso);
        }
    }

    Ok(())
}

pub fn cmd_dump(_args: &[String]) -> Result<()> {
    let cfg: TutuConfig = receive_struct(TUTU_CMD_GET_CONFIG, TUTU_ATTR_CONFIG, None)?;
    let t = chrono::Local::now().format("%Y-%m-%d %H:%M:%S %Z");

    println!("#!/sbin/ktuctl script -");
    println!("# Auto-generated by \"ktuctl dump\" on {}\n", t);

    if cfg.is_server != 0 {
        println!("server max-age {}\n", cfg.session_max_age);
        dump_structs(
            TUTU_CMD_GET_USER_INFO,
            TUTU_ATTR_USER_INFO,
            |u: &TutuUserInfo| {
                println!(
                    "server-add {} addr {} icmp-id {} port {}{}",
                    resolve_hostname(u.uid, true),
                    ip_to_string(&u.value.address),
                    ntohs(u.value.icmp_id),
                    ntohs(u.value.dport),
                    format_comment(&u.value.comment, true)
                );
                Ok(())
            },
        )?;
    } else {
        println!("client");
        dump_structs(TUTU_CMD_GET_EGRESS, TUTU_ATTR_EGRESS, |e: &TutuEgress| {
            if ntohs(e.key.port) != 0 {
                println!(
                    "client-add {} addr {} port {}{}",
                    resolve_hostname(e.value.uid, true),
                    ip_to_string(&e.key.address),
                    ntohs(e.key.port),
                    format_comment(&e.value.comment, true)
                );
            }
            Ok(())
        })?;
    }

    Ok(())
}

pub fn cmd_version(_args: &[String]) -> Result<()> {
    println!("{}: 1.0.0 (Rust Port)", PROJECT_NAME);
    Ok(())
}

pub fn cmd_script(args: &[String]) -> Result<()> {
    if args.is_empty() {
        bail!("usage: ktuctl script <file>");
    }

    let path = &args[0];
    let file: Box<dyn BufRead> = if path == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(File::open(path)?))
    };

    for (line_num, line) in file.lines().enumerate() {
        let line = line?;
        let raw_line = line.trim();
        if raw_line.is_empty() || raw_line.starts_with('#') {
            continue;
        }

        let sub_commands: Vec<&str> = raw_line.split(';').collect();
        for (sub_idx, sub_cmd_str) in sub_commands.iter().enumerate() {
            let sub_cmd_str = sub_cmd_str.trim();
            if sub_cmd_str.is_empty() {
                continue;
            }

            let line_args = shlex::split(sub_cmd_str).ok_or_else(|| anyhow!("parse error"))?;
            if line_args.is_empty() {
                continue;
            }

            let cmd = &line_args[0];
            let cmd_args = &line_args[1..];

            let res = match cmd.as_str() {
                "load" => cmd_load(cmd_args),
                "unload" => cmd_unload(cmd_args),
                "server" => cmd_server(cmd_args),
                "client" => cmd_client(cmd_args),
                "client-add" => cmd_client_add(cmd_args),
                "client-del" => cmd_client_del(cmd_args),
                "server-add" => cmd_server_add(cmd_args),
                "server-del" => cmd_server_del(cmd_args),
                "status" => cmd_status(cmd_args),
                "dump" => cmd_dump(cmd_args),
                "version" => cmd_version(cmd_args),
                "reaper" => {
                    info!("Obsolete");
                    Ok(())
                }
                _ => {
                    error!(
                        "Line {} (cmd {}): Unknown command '{}'",
                        line_num + 1,
                        sub_idx + 1,
                        cmd
                    );
                    Ok(())
                }
            };

            if let Err(e) = res {
                bail!(
                    "line {} (cmd {}) [{}]: {}",
                    line_num + 1,
                    sub_idx + 1,
                    cmd,
                    e
                );
            }
        }
    }
    Ok(())
}
