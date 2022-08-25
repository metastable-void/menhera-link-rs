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

use log::info;
use clap::{Parser, Subcommand, ArgGroup};
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
  let base64_shared_secret = base64::encode(&shared_secret_data);
  let mut f = fs::File::create(&path).await?;
  let mut permissions = f.metadata().await?.permissions();
  permissions.set_mode(0o600);
  assert_eq!(permissions.mode(), 0o600);
  f.set_permissions(permissions).await?;
  f.write_all(&base64_shared_secret.as_bytes()).await?;
  info!("Shared secret file created: {:?}", &path);
  Ok(())
}

async fn create(options: CreateOptions) -> Result<(), Box<dyn std::error::Error>> {
  let ip_version: IpVersion;
  if options.ipv4 {
    ip_version = IpVersion::V4;
  } else {
    ip_version = IpVersion::V6;
  }

  let shared_secret_base64 = fs::read_to_string(options.shared_key).await?;
  let shared_secret = base64::decode(shared_secret_base64)?;
  assert_eq!(shared_secret.len(), 32);
  let mut server = Server::new(ip_version, shared_secret.as_slice(), &options.local, &options.remote, &options.dev_name, options.mtu).await?;
  server.run().await?;
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
