mod cli;
mod commands;
mod config;
mod helper;
mod netlink;
mod uid_map;

use crate::cli::*;
use crate::commands::*;
use crate::config::*;
use crate::helper::*;

use anyhow::Result;
use clap::Parser;
use log::{error, info};

fn main() -> Result<()> {
    env_logger::init();

    if let Err(e) = UID_MAP
        .write()
        .expect("rwlock poisoned")
        .load(UID_CONFIG_PATH)
    {
        eprintln!("Warning: failed to load uid map: {}", e);
    }

    let cli = Cli::parse();

    {
        let mut flags = GLOBAL_FLAGS.write().expect("rwlock poisoned");
        flags.numeric = cli.numeric;
        flags.debug = cli.debug;
        if cli.ipv4 {
            flags.ip_family = Some("ip4".into());
        }
        if cli.ipv6 {
            flags.ip_family = Some("ip6".into());
        }
    }

    let mut all_args = cli.args.clone();

    if let Some(cmd) = cli.command {
        match cmd {
            Commands::Load { args } => return cmd_load(&args),
            Commands::Unload { args } => return cmd_unload(&args),
            Commands::Server { args } => return cmd_server(&args),
            Commands::Client { args } => return cmd_client(&args),
            Commands::ClientAdd { args } => return cmd_client_add(&args),
            Commands::ClientDel { args } => return cmd_client_del(&args),
            Commands::ServerAdd { args } => return cmd_server_add(&args),
            Commands::ServerDel { args } => return cmd_server_del(&args),
            Commands::Status { args } => return cmd_status(&args),
            Commands::Dump { args } => return cmd_dump(&args),
            Commands::Reaper { args } => return cmd_script(&args),
            Commands::Version { args } => return cmd_version(&args),
            Commands::Script { args } => return cmd_script(&args),
        }
    }

    if all_args.is_empty() {
        all_args = vec!["status".to_string()];
    }

    let subcmd = &all_args[0];
    let cmd_args = &all_args[1..];

    match subcmd.as_str() {
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
        "reaper" => {
            info!("Obsolete");
            Ok(())
        }
        "version" => cmd_version(cmd_args),
        "script" => cmd_script(cmd_args),
        "tui" => {
            println!("TUI not implemented in Rust port");
            Ok(())
        }
        _ => {
            error!("error: unknown command '{}'", subcmd);
            Ok(())
        }
    }
}
