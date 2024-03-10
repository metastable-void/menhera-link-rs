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

use log::LevelFilter;
use clap::{Parser, Subcommand, ArgGroup, ValueEnum};
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use rand::{thread_rng, Rng};
use tokio::fs;
use std::os::unix::fs::PermissionsExt;
use menhera_link::{Server, IpVersion};

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(subcommand)]
  command: Commands,

  /// Logging level
  #[clap(value_enum, value_parser, short = 'L', long, default_value_t = LogLevel::Info)]
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
  shared_key: Option<PathBuf>,

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

  let server = if let Some(shared_key) = options.shared_key {
    let shared_secret_base64 = fs::read(shared_key).await?;
    let shared_secret_base64 = shared_secret_base64.into_iter().filter(|b| !b" \n\t\r\x0b\x0c".contains(b));
    let shared_secret_base64 = Vec::from_iter(shared_secret_base64);
    let shared_secret = base64::decode(shared_secret_base64)?;
    assert_eq!(shared_secret.len(), 32);
    Server::new(ip_version, shared_secret.as_slice(), &options.local, &options.remote, &options.dev_name, options.mtu).await?
  } else {
    Server::new_plain(ip_version, &options.local, &options.remote, &options.dev_name, options.mtu).await?
  };
  
  server.run().await?;
  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  let args = Args::parse();
  env_logger::builder()
    .default_format()
    .write_style(env_logger::WriteStyle::Never)
    .filter_level(match args.log_level {
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
    })
    .init();
  
  match args.command {
    Commands::Create { options } => {
      return create(options).await;
    }

    Commands::GenerateSharedSecret { path } => {
      return generate_shared_secret(path).await;
    }
  }
}
