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

use log::{trace, info};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use tokio_tun::{TunBuilder, Tun};
use rand::{thread_rng, Rng};
use std::{io, net::{SocketAddr, ToSocketAddrs}};
use tokio::{net::UdpSocket, io::AsyncWriteExt};
use tokio::io::AsyncReadExt;

fn create_tap(name: &str, mtu: i32) -> Result<Tun, Box<dyn std::error::Error>> {
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
    return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Invalid key length")));
  }
  let nonce = Nonce::from_slice(&iv);
  let ciphertext = cipher.encrypt(nonce, plaintext)?;
  Ok([&iv as &[u8], &ciphertext.as_slice()].concat())
}

pub fn decrypt_aes_gcm(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
  //
  let (iv, ciphertext) = ciphertext.split_at(12);
  if 12 != iv.len() {
    return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Invalid iv length")));
  }
  let cipher;
  if let Ok(successful_cipher) = Aes256Gcm::new_from_slice(key.as_ref()) {
    cipher = successful_cipher;
  } else {
    return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Invalid key length")));
  }
  let nonce = Nonce::from_slice(&iv);
  let plaintext = cipher.decrypt(nonce, ciphertext)?;
  Ok(plaintext)
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IpVersion {
  V4,
  V6,
}

pub fn resolve_socket_addr(ip_version: IpVersion, addr: &str) -> Result<SocketAddr, Box<dyn std::error::Error>> {
  let sockaddrs = addr.to_socket_addrs()?;
  let found_sockaddr: SocketAddr;
  'iter_sockaddrs: loop {
    for sockaddr in sockaddrs {
      match sockaddr {
        SocketAddr::V4(v4addr) => {
          if let IpVersion::V4 = ip_version {
            found_sockaddr = SocketAddr::V4(v4addr);
            break 'iter_sockaddrs;
          }
        }
        SocketAddr::V6(v6addr) => {
          if let IpVersion::V6 = ip_version {
            found_sockaddr = SocketAddr::V6(v6addr);
            break 'iter_sockaddrs;
          }
        }
      }
    }
    return Err(Box::new(io::Error::new(io::ErrorKind::NotFound, "Could not resolve")) as Box<dyn std::error::Error>);
  }
  Ok(found_sockaddr)
}

pub enum Packet {
  SimpleEncryption {
    ciphertext: Vec<u8>,
  },
}

impl Packet {
  pub fn new(buf: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
    let (packet_type_arr, buf) = buf.split_at(1);
    if packet_type_arr.len() != 1 {
      return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Missing packet type")));
    }
    let packet_type = packet_type_arr[0];
    match packet_type {
      0 => {
        // SimpleEncryption
        return Ok(Packet::SimpleEncryption { ciphertext: buf.to_vec() });
      }

      _ => {
        return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Unrecognized packet type")));
      }
    }
  }

  pub fn as_vec(&self) -> Vec<u8> {
    let encoded;
    match &self {
      Self::SimpleEncryption { ciphertext } => {
        let packet_type_arr = [0u8];
        encoded = [&packet_type_arr as &[u8], ciphertext.as_slice()].concat();
      }
    }
    encoded
  }
}

pub struct Server {
  socket: UdpSocket,
  tap: Tun,
  remote_addr_str: String,
  shared_secret: Vec<u8>,
  ip_version: IpVersion,
}

impl Server {
  pub async fn new(ip_version: IpVersion, shared_secret: &[u8], bind_addr: &str, remote_addr: &str, device_name: &str, mtu: i32) -> Result<Self, Box<dyn std::error::Error>> {
    let bind_addr = resolve_socket_addr(ip_version, bind_addr)?;
    let resolved_remote_addr = resolve_socket_addr(ip_version, remote_addr)?;
    info!("Local: {:?}", &bind_addr);
    info!("Remote: {:?}", &resolved_remote_addr);

    let socket = UdpSocket::bind(&bind_addr).await?;
    info!("Listening on: {}", socket.local_addr()?);
    let tap = create_tap(device_name, mtu)?;
    Ok(Server {
      socket,
      tap,
      shared_secret: shared_secret.to_owned(),
      remote_addr_str: remote_addr.to_owned(),
      ip_version,
    })
  }

  pub async fn run(self: &mut Self) -> Result<(), Box<dyn std::error::Error>> {
    let Server {
      socket,
      tap,
      shared_secret,
      remote_addr_str,
      ip_version,
    } = self;
    let mut tap_buf = [0u8; 65536];
    let mut socket_buf = [0u8; 65536];
    info!("Server running...");
    loop {
      tokio::select! {
        Ok(nread) = tap.read(&mut tap_buf) => {
          let plaintext = &tap_buf[.. nread];
          if let Ok(remote_addr) = resolve_socket_addr(*ip_version, &remote_addr_str) {
            if let Ok(ciphertext) = encrypt_aes_gcm(&shared_secret, plaintext) {
              let packet = Packet::SimpleEncryption { ciphertext };
              trace!("Sending {} bytes to {:?}", nread, &remote_addr);
              socket.send_to(&packet.as_vec(), &remote_addr.clone()).await?;
            }
          }
        }

        Ok((nread, peer)) = socket.recv_from(&mut socket_buf) => {
          if let Ok(packet) = Packet::new(&socket_buf[.. nread]) {
            trace!("Received {} bytes from {:?}", nread, peer);
            match packet {
              Packet::SimpleEncryption { ciphertext } => {
                if let Ok(plaintext) = decrypt_aes_gcm(&shared_secret, &ciphertext) {
                  tap.write_all(&plaintext).await?;
                }
              }
              _ => {
                // NOOP
              }
            }
          }

        }
      }
    }
  }
}
