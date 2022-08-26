// -*- indent-tabs-mode: nil; tab-width: 2; -*-
// vim: set ts=&2 sw=2 et ai :

/*
  menhera-link
  Copyright (C) 2022 Menhera.org

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

use syslog::{Facility, Formatter3164, BasicLogger};
use log::{LevelFilter, info};
use clap::{Parser, Subcommand, ArgGroup, ValueEnum};
use tokio::io::AsyncWriteExt;
use std::path::{PathBuf, Path};
use rand::{thread_rng, Rng};
use tokio::fs;
use std::os::unix::fs::PermissionsExt;
use menhera_link::{Server, IpVersion};
use daemonize_me::Daemon;
use nix::{sys::{signal::{kill, Signal}}, unistd::Pid};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(subcommand)]
  command: Commands,

  /// Logging level
  #[clap(arg_enum, value_parser, short = 'L', long, default_value_t = LogLevel::Info)]
  log_level: LogLevel,
}

#[derive(clap::Args)]
struct CreateOptions {
  /// Device name to create
  dev_name: String,

  /// Use tunneling over IPv4.
  #[clap(short = '4', long, action)]
  ipv4: bool,

  /// Use tunneling over IPv6.
  #[clap(short = '6', long, action)]
  ipv6: bool,

  /// Device MTU
  #[clap(short, long, default_value_t = 1350i32, value_parser = clap::value_parser!(i32).range(576..65535))]
  mtu: i32,

  /// Path to shared key file
  #[clap(short, long, value_parser, id = "SHARED_KEY_PATH")]
  shared_key: PathBuf,

  /// Local VPN endpoint
  #[clap(short, long, value_parser, id = "ADDR:PORT")]
  local: String,

  /// Remote VPN endpoint
  #[clap(short, long, value_parser, id = "HOST:PORT")]
  remote: String,

  /// Do not daemonize (run in foreground)
  #[clap(short = 'f', long, value_parser)]
  no_daemon: bool,

  /// Path to store PID value in
  #[clap(short, long, value_parser)]
  pid_file: Option<PathBuf>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum LogLevel {
  Trace,
  Debug,
  Info,
  Warn,
  Error,
}

#[derive(Subcommand)]
enum Commands {
  /// Creates a tunnel (tap) interface.
  #[clap(group(
    ArgGroup::new("ip_version")
      .required(true)
      .args(&["ipv4", "ipv6"]),
  ))]
  Create {
    #[clap(flatten)]
    options: CreateOptions,
  },

  /// Generates a shared secret file.
  GenerateSharedSecret {
    path: PathBuf,
  },

  /// Delete a created interface and terminate the associated daemon
  Delete {
    /// Device name to delete
    dev_name: String,

    /// Path to store PID value in
    #[clap(short, long, value_parser)]
    pid_file: Option<PathBuf>,
  }
}

async fn generate_shared_secret(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
  let shared_secret_data: [u8; 32] = thread_rng().gen();
  let base64_shared_secret = base64::encode(&shared_secret_data);
  let mut f = fs::File::create(&path).await?;
  let mut permissions = f.metadata().await?.permissions();
  permissions.set_mode(0o600);
  assert_eq!(permissions.mode(), 0o600);
  f.set_permissions(permissions).await?;
  f.write_all(&base64_shared_secret.as_bytes()).await?;
  println!("Shared secret file created: {:?}", &path);
  Ok(())
}

async fn delete(dev_name: &str, pid_file: Option<PathBuf>) -> Result<(), Box<dyn std::error::Error>> {
  let default_pid_path = format!("/var/run/menhera-link_{}.pid", dev_name);
  let pid_file = match pid_file {
    Some(path) => {
      path
    }
    None => {
      Path::new::<str>(&default_pid_path).to_path_buf()
    }
  };
  let pid_str = fs::read_to_string(pid_file).await?;
  let pid: u32;
  let parts = pid_str.split_whitespace().map(|s| s.parse::<u32>());
  'parse_pid_block: loop {
    for res in parts {
      match res {
        Ok(retrieved_pid) => {
          pid = retrieved_pid;
          break 'parse_pid_block;
        }
        Err(_) => {
          return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid PID file contents")));
        }
      }
    }
    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid PID file contents")));
  }
  let nix_pid = Pid::from_raw(pid.try_into().unwrap());
  kill(nix_pid, Signal::SIGTERM)?;
  Ok(())
}

async fn create(options: CreateOptions) -> Result<(), Box<dyn std::error::Error>> {
  let ip_version: IpVersion;
  if options.ipv4 {
    ip_version = IpVersion::V4;
  } else {
    ip_version = IpVersion::V6;
  }

  if options.mtu < 576 || options.mtu > 65535 {
    return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid MTU size")));
  }

  let shared_secret_base64 = fs::read(options.shared_key).await?;
  let shared_secret_base64 = shared_secret_base64.into_iter().filter(|b| !b" \n\t\r\x0b\x0c".contains(b));
  let shared_secret_base64 = Vec::from_iter(shared_secret_base64);
  let shared_secret = base64::decode(shared_secret_base64)?;
  assert_eq!(shared_secret.len(), 32);
  let server = Server::new(ip_version, shared_secret.as_slice(), &options.local, &options.remote, &options.dev_name, options.mtu).await?;
  if !options.no_daemon {
    let stdin = std::fs::File::open("/dev/null")?;
    let stdout = std::fs::File::open("/dev/null")?;
    let stderr = std::fs::File::open("/dev/null")?;
    let default_pid_path = format!("/var/run/menhera-link_{}.pid", options.dev_name);
    let pid_file = match options.pid_file {
      Some(path) => {
        path
      }
      None => {
        Path::new::<str>(&default_pid_path).to_path_buf()
      }
    };
    let daemon = Daemon::new()
      .pid_file(pid_file, Some(false))
      .umask(0o000)
      .work_dir(Path::new("/"))
      .stdin(stdin)
      .stdout(stdout)
      .stderr(stderr)
      .start();
    
    match daemon {
      Ok(_) => {
        let pid = std::process::id();
        info!("Daemonized (pid = {})", pid);
      }
      Err(e) => {
        return Err(Box::new(e));
      }
    }
  }
  server.run().await?;
  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let formatter = Formatter3164 {
    facility: Facility::LOG_DAEMON,
    hostname: None,
    process: "menhera-link".into(),
    pid: 0,
  };
  let logger = match syslog::unix(formatter) {
    Err(e) => {
      println!("impossible to connect to syslog: {:?}", e);
      return Ok(());
    },
    Ok(logger) => logger,
  };
  let args = Args::parse();

  log::set_boxed_logger(Box::new(BasicLogger::new(logger)))
    .map(|()| log::set_max_level(match args.log_level {
      LogLevel::Trace => {
        LevelFilter::Trace
      }
      LogLevel::Debug => {
        LevelFilter::Debug
      }
      LogLevel::Info => {
        LevelFilter::Info
      }
      LogLevel::Warn => {
        LevelFilter::Warn
      }
      LogLevel::Error => {
        LevelFilter::Error
      }
    }))?;
  
  match args.command {
    Commands::Create { options } => {
      return create(options).await;
    }

    Commands::GenerateSharedSecret { path } => {
      return generate_shared_secret(path).await;
    }

    Commands::Delete { dev_name, pid_file } => {
      return delete(&dev_name, pid_file).await;
    }
  }
}
