use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "ktuctl-rs", about = "Control utility for tutuicmptunnel")]
pub struct Cli {
    #[arg(short = 'n', long = "numeric", help = "numeric output for UIDs")]
    pub numeric: bool,

    #[arg(short = 'd', long = "debug", help = "debug mode")]
    pub debug: bool,

    #[arg(short = '4', help = "IPv4 only")]
    pub ipv4: bool,

    #[arg(short = '6', help = "IPv6 only")]
    pub ipv6: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,

    #[arg(allow_hyphen_values = true, trailing_var_arg = true)]
    pub args: Vec<String>,
}

#[derive(Subcommand)]
pub enum Commands {
    Load { args: Vec<String> },
    Unload { args: Vec<String> },
    Server { args: Vec<String> },
    Client { args: Vec<String> },
    ClientAdd { args: Vec<String> },
    ClientDel { args: Vec<String> },
    ServerAdd { args: Vec<String> },
    ServerDel { args: Vec<String> },
    Status { args: Vec<String> },
    Dump { args: Vec<String> },
    Reaper { args: Vec<String> },
    Version { args: Vec<String> },
    Script { args: Vec<String> },
}
