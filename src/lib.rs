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
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use tokio_tun::{TunBuilder, Tun};
use rand::{thread_rng, Rng};
use std::{io, net::SocketAddr};
use tokio::net::UdpSocket;
use tokio::io::AsyncReadExt;

pub fn create_tap(name: &str, mtu: i32) -> Result<Tun, Box<dyn std::error::Error>> {
  let tap = TunBuilder::new()
    .tap(true)
    .name(name)
    .packet_info(false)
    .mtu(mtu)
    .up()
    .try_build()?;
  
  Ok(tap)
}

pub fn encrypt_aes_gcm(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
  let iv: [u8; 12] = thread_rng().gen();
  let cipher;
  if let Ok(successful_cipher) = Aes256Gcm::new_from_slice(key.as_ref()) {
    cipher = successful_cipher;
  } else {
    return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Invalid length")));
  }
  let nonce = Nonce::from_slice(&iv);
  let ciphertext = cipher.encrypt(nonce, plaintext)?;
  Ok([&iv as &[u8], &ciphertext.as_slice()].concat())
}

pub struct Server {
  socket: UdpSocket,
  tap: Tun,
}

impl Server {
  pub async fn new(bind_addr: SocketAddr, device_name: &str, mtu: i32) -> Result<Self, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind(&bind_addr).await?;
    info!("Listening on: {}", socket.local_addr()?);
    let tap = create_tap(device_name, mtu)?;
    Ok(Server {
      socket,
      tap,
    })
  }

  pub async fn run() -> Result<(), std::io::Error> {
    Ok(())
  }
}
