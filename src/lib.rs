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


use log::{trace, info, warn, debug};
use std::{time::Instant, sync::Arc};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, // Or `Aes128Gcm`
};
use tokio_tun::{TunBuilder, Tun};
use rand::{thread_rng, Rng};
use std::{io, net::{SocketAddr, ToSocketAddrs}};
use tokio::{net::UdpSocket, io::AsyncWriteExt};
use tokio::io::AsyncReadExt;
use tokio::sync::mpsc;

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

#[non_exhaustive]
pub enum Packet {
  SimpleEncryption {
    ciphertext: Vec<u8>,
  },

  NoEncryption {
    data: Vec<u8>,
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

      1 => {
        // NoEncryption
        return Ok(Packet::NoEncryption { data: buf.to_vec() });
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
      Self::NoEncryption { data } => {
        let packet_type_arr = [1u8];
        encoded = [&packet_type_arr as &[u8], data.as_slice()].concat();
      }
    }
    encoded
  }
}

pub struct Server {
  socket: Arc<UdpSocket>,
  tap: Tun,
  remote_addr_str: String,
  shared_secret: Option<Arc<Vec<u8>>>,
  ip_version: IpVersion,
}

impl Server {
  pub async fn new(ip_version: IpVersion, shared_secret: &[u8], bind_addr: &str, remote_addr: &str, device_name: &str, mtu: i32) -> Result<Self, Box<dyn std::error::Error>> {
    let bind_addr = resolve_socket_addr(ip_version, bind_addr)?;
    let resolved_remote_addr = resolve_socket_addr(ip_version, remote_addr)?;
    info!("Local: {:?}", &bind_addr);
    info!("Remote: {:?}", &resolved_remote_addr);

    let socket = Arc::new(UdpSocket::bind(&bind_addr).await?);
    info!("Listening on: {}", socket.local_addr()?);
    let tap = create_tap(device_name, mtu)?;
    Ok(Server {
      socket,
      tap,
      shared_secret: Some(Arc::new(shared_secret.to_owned())),
      remote_addr_str: remote_addr.to_owned(),
      ip_version,
    })
  }

  async fn run_plain(self: Self) -> Result<(), Box<dyn stf::error::Error>> {
    let Server {
      socket,
      tap,
      shared_secret,
      remote_addr_str,
      ip_version,
    } = self;

    if let Some(_) = shared_secret {
      return Err(Box::new(io::Error::new(io::ErrorKind::InvalidInput, "Shared secret not provided")));
    }

    let mut tap_buf = [0u8; 65536];
    let mut socket_buf = [0u8; 65536];

    let mut remote_addr_cache: Option<SocketAddr> = None;
    let mut remote_addr_cached_time = Instant::now();

    let socket_receive = socket.clone();
    let socket_send = socket_receive.clone();
    let (mut tap_reader, mut tap_writer) = tokio::io::split(tap);

    loop {
      tokio::select! {
        Ok(nread) = tap_reader.read(&mut tap_buf) => {
          let plaintext = tap_buf[.. nread];

          if let Some(_remote_addr) = remote_addr_cache {
            let elapsed = remote_addr_cached_time.elapsed();
            if elapsed.as_secs() > 60 {
              if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
                remote_addr_cache = Some(remote_addr);
                remote_addr_cached_time = Instant::now();
              }
            }
          } else {
            if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
              remote_addr_cache = Some(remote_addr);
              remote_addr_cached_time = Instant::now();
            }
          }

          if let Some(remote_addr) = remote_addr_cache {
            let packet = Packet::NoEncryption { data: plaintext.to_vec() };
            let packet_data = packet.as_vec();
            if let Ok(nsent) = socket_send.send_to(&packet_data, &remote_addr.clone()).await {
              trace!("Sent {} bytes to {:?}", nsent, &remote_addr);
            } else {
              warn!("Failed to send data to {:?}", &remote_addr);
            }
          } else {
            info!("Remote address not resolved (yet). Discarding packet...");
          }
        }

        Ok((nread, peer)) = socket_receive.recv_from(&mut socket_buf) => {
          if let Ok(packet) = Packet::new(&socket_buf[.. nread]) {
            trace!("Received {} bytes from {:?}", nread, peer);

            if let Some(_remote_addr) = remote_addr_cache {
              let elapsed = remote_addr_cached_time.elapsed();
              if elapsed.as_secs() > 60 {
                if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
                  remote_addr_cache = Some(remote_addr);
                  remote_addr_cached_time = Instant::now();
                }
              }
            } else {
              if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
                remote_addr_cache = Some(remote_addr);
                remote_addr_cached_time = Instant::now();
              }
            }
  
            if let Some(remote_addr) = remote_addr_cache {
              if peer != remote_addr {
                info!("Received packet from unexpected address. Discarding...");
              } else {
                match packet {
                  Packet::NoEncryption { data } => {
                    if let Ok(()) = tap_writer.write_all(&data).await {
                      trace!("{} bytes data written to tap interface", &data.len());
                    } else {
                      warn!("Failed to write data to tap interface");
                    }
                  }
                  _ => {
                    // NOOP
                  }
                }
              }
            } else {
              info!("Remote address not resolved (yet). Discarding incoming packet...");
            }
          }
        }
      }
    }
  }

  #[allow(unreachable_patterns)]
  pub async fn run(self: Self) -> Result<(), Box<dyn std::error::Error>> {
    let Server {
      socket,
      tap,
      shared_secret,
      remote_addr_str,
      ip_version,
    } = self;

    if let None = shared_secret {
      return Server::run_plain(Server {
        socket,
        tap,
        shared_secret,
        remote_addr_str,
        ip_version,
      }).await;
    }

    let shared_secret = shared_secret.unwrap();
    
    let mut tap_buf = [0u8; 65536];
    let mut socket_buf = [0u8; 65536];
    info!("Server running...");
    let mut remote_addr_cache: Option<SocketAddr> = None;
    let mut remote_addr_cached_time = Instant::now();
    let (encrypt_tx, mut encrypt_rx) = mpsc::channel::<Vec<u8>>(32);
    let (decrypt_tx, mut decrypt_rx) = mpsc::channel::<Vec<u8>>(32);
    let socket_receive = socket.clone();
    let socket_send = socket_receive.clone();
    let (mut tap_reader, mut tap_writer) = tokio::io::split(tap);

    let copied_shared_secret = shared_secret.clone();
    let remote_addr_str = Arc::new(remote_addr_str.clone());
    tokio::spawn(async move {
      debug!("Encryption thread started");
      loop {
        if let Some(plaintext) = encrypt_rx.recv().await {
          let successful_ciphertext: Vec<u8>;
          if let Ok(ciphertext) = encrypt_aes_gcm(&copied_shared_secret, &plaintext.as_slice()) {
            successful_ciphertext = ciphertext;
          } else {
            warn!("Encryption error");
            continue;
          }
          if let Some(_remote_addr) = remote_addr_cache {
            let elapsed = remote_addr_cached_time.elapsed();
            if elapsed.as_secs() > 60 {
              if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
                remote_addr_cache = Some(remote_addr);
                remote_addr_cached_time = Instant::now();
              }
            }
          } else {
            if let Ok(remote_addr) = resolve_socket_addr(ip_version, &remote_addr_str) {
              remote_addr_cache = Some(remote_addr);
              remote_addr_cached_time = Instant::now();
            }
          }
          if let Some(remote_addr) = remote_addr_cache {
            let packet = Packet::SimpleEncryption { ciphertext: successful_ciphertext };
            let packet_data = &packet.as_vec();
            if let Ok(nsent) = socket_send.send_to(&packet_data, &remote_addr.clone()).await {
              trace!("Sent {} bytes to {:?}", nsent, &remote_addr);
            } else {
              warn!("Failed to send data to {:?}", &remote_addr);
            }
          } else {
            info!("Remote address not resolved (yet). Discarding packet...");
          }
        }
      }
      //
    });

    let copied_shared_secret = shared_secret.clone();
    tokio::spawn(async move {
      debug!("Decryption thread started");
      loop {
        if let Some(ciphertext) = decrypt_rx.recv().await {
          let successful_plaintext: Vec<u8>;
          if let Ok(plaintext) = decrypt_aes_gcm(&copied_shared_secret, &ciphertext) {
            successful_plaintext = plaintext;
          } else {
            warn!("Decryption error");
            continue;
          }
          if let Ok(()) = tap_writer.write_all(&successful_plaintext).await {
            trace!("{} bytes data written to tap interface", &successful_plaintext.len());
          } else {
            warn!("Failed to write data to tap interface");
          }
        }
      }
    });

    loop {
      tokio::select! {
        Ok(nread) = tap_reader.read(&mut tap_buf) => {
          let plaintext = tap_buf[.. nread].to_owned();
          encrypt_tx.send(plaintext).await?;
        }

        Ok((nread, peer)) = socket_receive.recv_from(&mut socket_buf) => {
          if let Ok(packet) = Packet::new(&socket_buf[.. nread]) {
            trace!("Received {} bytes from {:?}", nread, peer);
            match packet {
              Packet::SimpleEncryption { ciphertext } => {
                decrypt_tx.send(ciphertext).await?;
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
