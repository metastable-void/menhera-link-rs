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

use log::{debug, info, warn, error};
use clap::{Parser, Subcommand, ArgGroup};
use tokio::io::AsyncWriteExt;
use std::path::PathBuf;
use std::net::{SocketAddr, ToSocketAddrs};
use std::fmt;
use std::sync::Arc;
use rand::{thread_rng, Rng};
use tokio::fs;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Clone)]
struct MenheraLinkError(Arc<str>);

impl MenheraLinkError {
  pub fn new(description: &str) -> Self {
    MenheraLinkError(Arc::from(description))
  }
}

impl fmt::Display for MenheraLinkError {
  fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
    write!(f, "MenheraLinkError: {}", self.0)
  }
}

impl std::error::Error for MenheraLinkError {}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
  #[clap(subcommand)]
  command: Commands,
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
  #[clap(short, long, default_value_t = 1300i32)]
  mtu: i32,

  /// Path to shared key file
  #[clap(short, long, value_parser, id = "PATH")]
  shared_key: PathBuf,

  /// Local VPN endpoint
  #[clap(short, long, value_parser, id = "ADDR:PORT")]
  local: String,

  /// Remote VPN endpoint
  #[clap(short, long, value_parser, id = "HOST:PORT")]
  remote: String,
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
  let mut f = fs::File::create(&path).await?;
  let mut permissions = f.metadata().await?.permissions();
  permissions.set_mode(0o600);
  assert_eq!(permissions.mode(), 0o600);
  f.set_permissions(permissions).await?;
  f.write_all(&shared_secret_data as &[u8]).await?;
  info!("Shared secret file created: {:?}", &path);
  Ok(())
}

async fn create(options: CreateOptions) -> Result<(), Box<dyn std::error::Error>> {
  // Re-resolve later to catch up with DDNS changes
  let local = options.local.clone();
  let remote = options.remote.clone();

  let local_sockaddrs = options.local.to_socket_addrs()?;
  let local_sockaddr: SocketAddr;
  'iter_local_sockaddrs: loop {
    for sockaddr in local_sockaddrs {
      match sockaddr {
        SocketAddr::V4(v4addr) => {
          if options.ipv4 {
            local_sockaddr = SocketAddr::V4(v4addr);
            break 'iter_local_sockaddrs;
          }
        }
        SocketAddr::V6(v6addr) => {
          if options.ipv6 {
            local_sockaddr = SocketAddr::V6(v6addr);
            break 'iter_local_sockaddrs;
          }
        }
      }
    }
    return Err(Box::new(MenheraLinkError::new("")) as Box<dyn std::error::Error>);
  }
  let remote_sockaddrs = options.remote.to_socket_addrs()?;
  let remote_sockaddr: SocketAddr;
  'iter_remote_sockaddrs: loop {
    for sockaddr in remote_sockaddrs {
      match sockaddr {
        SocketAddr::V4(v4addr) => {
          if options.ipv4 {
            remote_sockaddr = SocketAddr::V4(v4addr);
            break 'iter_remote_sockaddrs;
          }
        }
        SocketAddr::V6(v6addr) => {
          if options.ipv6 {
            remote_sockaddr = SocketAddr::V6(v6addr);
            break 'iter_remote_sockaddrs;
          }
        }
      }
    }
    return Err(Box::new(MenheraLinkError::new("")) as Box<dyn std::error::Error>);
  }
  info!("Local: {:?}", &local_sockaddr);
  info!("Remote: {:?}", &remote_sockaddr);
  Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
  pretty_env_logger::init();
  let args = Args::parse();
  match args.command {
    Commands::Create { options } => {
      return create(options).await;
    }

    Commands::GenerateSharedSecret { path } => {
      return generate_shared_secret(path).await;
    }
  }
}
