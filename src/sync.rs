// sync.rs - synchronous (blocking) IO networking
// Copyright (C) 2021  David Anthony Stainton.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

extern crate snow;
extern crate x25519_dalek_ng;

use std::net::{TcpStream, Shutdown};
use std::io::prelude::*;
use std::sync::{Arc, Mutex};

use super::commands::{Command};
use super::errors::{HandshakeError, ReceiveMessageError, SendMessageError};
use super::messages::{MessageBuilder, SessionConfig, PeerCredentials};
use super::constants::{NOISE_HANDSHAKE_MESSAGE1_SIZE, NOISE_HANDSHAKE_MESSAGE2_SIZE,
                       NOISE_HANDSHAKE_MESSAGE3_SIZE};


const MAC_LEN: usize = 16;
const MAX_MSG_LEN: usize = 1_048_576;

/// A mixnet link layer protocol session.
pub struct Session {
    reader_tcp_stream: Option<TcpStream>,
    writer_tcp_stream: Option<TcpStream>,
    is_initiator: bool,
    handshake_builder: Option<MessageBuilder>,
    transport_builder: Option<Arc<Mutex<MessageBuilder>>>,
}

impl Clone for Session {
    fn clone(&self) -> Session {
        Session {
            reader_tcp_stream: Some(self.reader_tcp_stream.as_ref().unwrap().try_clone().unwrap()),
            writer_tcp_stream: Some(self.writer_tcp_stream.as_ref().unwrap().try_clone().unwrap()),
            is_initiator: self.is_initiator,
            handshake_builder: None,
            transport_builder: self.transport_builder.clone(),
        }
    }
}

impl Session {
    pub fn new(cfg: SessionConfig, is_initiator: bool) -> Result<Session, HandshakeError> {
        Ok(Session{
            writer_tcp_stream: None,
            reader_tcp_stream: None,
            is_initiator,
            handshake_builder: Some(MessageBuilder::new(cfg, is_initiator)?),
            transport_builder: None,
        })
    }

    fn handshake(&mut self) -> Result<(), HandshakeError>{
        let tcp_reader = self.reader_tcp_stream.as_mut().unwrap();
        let tcp_writer = self.writer_tcp_stream.as_mut().unwrap();
        let factory = self.handshake_builder.as_mut().unwrap();
        if self.is_initiator {
            // -> (prologue), e, e1
            let client_handshake1 = factory.client_handshake1()?;
            tcp_writer.write_all(&client_handshake1)?;
            factory.sent_client_handshake1();

	    // <- e, ee, ekem1, s, es, (auth)
            let mut server_handshake1 = [0; NOISE_HANDSHAKE_MESSAGE2_SIZE];
            tcp_reader.read_exact(&mut server_handshake1)?;
            factory.received_server_handshake1(server_handshake1)?;

	    // -> s, se, (auth)
            let client_handshake2 = factory.client_handshake2()?;
            tcp_writer.write_all(&client_handshake2)?;
            factory.sent_client_handshake2();
        } else {
	    // -> (prologue), e, e1
            let mut client_handshake1 = [0u8; NOISE_HANDSHAKE_MESSAGE1_SIZE];
            tcp_reader.read_exact(&mut client_handshake1)?;
            let server_handshake1 = factory.received_client_handshake1(client_handshake1).unwrap();

	    // <- e, ee, ekem1, s, es, (auth)
            tcp_writer.write_all(&server_handshake1)?;
            factory.sent_server_handshake1();

	    // -> s, se, (auth)
            let mut client_handshake2 = [0u8; NOISE_HANDSHAKE_MESSAGE3_SIZE];
            tcp_reader.read_exact(&mut client_handshake2)?;
            factory.received_client_handshake2(client_handshake2).unwrap();
        }
        Ok(())
    }

    pub fn finalize_handshake(&mut self) -> Result<(), HandshakeError>{
        if self.is_initiator {
            let cmd = self.recv_command().unwrap();
            match cmd {
                Command::NoOp{} => return Ok(()),
                _ => return Err(HandshakeError::InvalidHandshakeFinalize),
            }
        }
        let cmd = Command::NoOp{};
        self.send_command(&cmd).unwrap();
        Ok(())
    }
        
    pub fn initialize(&mut self, tcp_stream: TcpStream) -> Result<(), HandshakeError>{
        let reader_tcp_stream = tcp_stream.try_clone()?;
        self.reader_tcp_stream = Some(reader_tcp_stream);
        self.writer_tcp_stream = Some(tcp_stream);
        self.handshake()?;
        Ok(())
    }

    pub fn into_transport_mode(mut self) -> Result<Self, HandshakeError> {
        Ok(Self {
            reader_tcp_stream: self.reader_tcp_stream,
            writer_tcp_stream: self.writer_tcp_stream,
            is_initiator: self.is_initiator,
            handshake_builder: None,
            transport_builder: Some(Arc::new(Mutex::new(self.handshake_builder.take().unwrap().into_transport_mode()?))),
        })
    }

    pub fn send_command(&mut self, cmd: &Command) -> Result<(), SendMessageError> {
        let ct = cmd.to_vec();
        let ct_len = MAC_LEN + ct.len();
        if ct_len > MAX_MSG_LEN {
            return Err(SendMessageError::InvalidMessageSize);
        }

        let mut to_send = vec![];
        to_send.extend(self.transport_builder.as_mut().unwrap().lock().unwrap().encrypt_message(&ct)?);

        self.transport_builder.as_mut().unwrap().lock().unwrap().rekey_outgoing();

        self.writer_tcp_stream.as_mut().unwrap().write_all(&to_send)?;
        Ok(())
    }

    pub fn recv_command(&mut self) -> Result<Command, ReceiveMessageError> {
        // Read, decrypt and parse the ciphertext header.
        let mut header_ciphertext = vec![0u8; MAC_LEN + 4];
        self.reader_tcp_stream.as_mut().unwrap().read_exact(&mut header_ciphertext)?;
        let ct_len = self.transport_builder.as_mut().unwrap().lock().unwrap().decrypt_message_header(&header_ciphertext.to_vec())?;

        // Read and decrypt the ciphertext.
        let mut ct = vec![0u8; ct_len as usize];
        self.reader_tcp_stream.as_mut().unwrap().read_exact(&mut ct)?;
        let body = self.transport_builder.as_mut().unwrap().lock().unwrap().decrypt_message(&ct)?;

        self.transport_builder.as_mut().unwrap().lock().unwrap().rekey_incoming();

        Ok(Command::from_bytes(&body)?)
    }

    pub fn close(&mut self) {
        self.transport_builder.as_mut().unwrap().lock().unwrap().rekey_outgoing();
        self.transport_builder.as_mut().unwrap().lock().unwrap().rekey_incoming();
        self.transport_builder.as_ref().unwrap().lock().unwrap().wipe();
        let _ = self.reader_tcp_stream.as_mut().unwrap().shutdown(Shutdown::Both);
        let _ = self.writer_tcp_stream.as_mut().unwrap().shutdown(Shutdown::Both);
    }

    pub fn peer_credentials(&self) -> &PeerCredentials {
        self.handshake_builder.as_ref().unwrap().peer_credentials()
    }

    pub fn clock_skew(&self) -> u32 {
        self.transport_builder.as_ref().unwrap().lock().unwrap().clock_skew()
    }

    pub fn from_client(&self) -> bool {
        assert!(!self.is_initiator);
        assert!(self.transport_builder.is_some());
        self.transport_builder.as_ref().unwrap().lock().unwrap().authenticator.is_peer_client()
    }
}

#[cfg(test)]
mod tests {
    extern crate rand_core;

    use std::{thread, time};
    use std::time::Duration;
    use std::net::TcpListener;
    use std::net::TcpStream;
    use std::collections::HashMap;

    use x25519_dalek_ng::{PublicKey, StaticSecret};

    use super::{Session, SessionConfig};
    use super::super::messages::{PeerAuthenticator, ProviderAuthenticatorState, ClientAuthenticatorState};
    use super::super::commands::{Command};
    use self::rand_core::OsRng;


    #[test]
    fn handshake_test() {
        let mut threads = vec![];
        let server_addr = "127.0.0.1:8000";
        let client_secret = StaticSecret::new(OsRng);
        let server_secret = StaticSecret::new(OsRng);

        let mut client_map = HashMap::new();
        client_map.insert(PublicKey::from(&client_secret), true);
        let provider_auth = ProviderAuthenticatorState {
            mix_map: HashMap::default(),
            client_map: client_map,
            from_client: false,
            from_mix: false,
        };
        let provider_authenticator = PeerAuthenticator::Provider(provider_auth);

        let client_auth = ClientAuthenticatorState{
            peer_public_key: PublicKey::from(&server_secret),
        };
        let client_authenticator = PeerAuthenticator::Client(client_auth);

        let server_keypair_clone = server_secret.clone();

        // server listener
        threads.push(thread::spawn(move|| {
            let listener = TcpListener::bind(server_addr.clone()).expect("could not start server");

            // server
            let server_config = SessionConfig {
                authenticator: provider_authenticator,
                authentication_key: server_secret,
                peer_public_key: None,
                additional_data: vec![],
            };
            let mut session = Session::new(server_config, false).unwrap();

            for connection in listener.incoming() {
                match connection {
                    Ok(stream) => {
                        session.initialize(stream).unwrap();

                        session = session.into_transport_mode().unwrap();
                        session.finalize_handshake().unwrap();
                        session.close();
                        return
                    }
                    Err(e) => { println!("connection failed {}", e); }
                }
            }
        }));

        // client dialer
        threads.push(thread::spawn(move|| {
            thread::sleep(Duration::from_secs(1));
            // client
            let client_config = SessionConfig {
                authenticator: client_authenticator,
                authentication_key: client_secret,
                peer_public_key: Some(PublicKey::from(&server_keypair_clone)),
                additional_data: vec![],
            };
            let mut session = Session::new(client_config, true).unwrap();

            let stream = TcpStream::connect(server_addr.clone()).expect("connection failed");
            session.initialize(stream).unwrap();

            session = session.into_transport_mode().unwrap();
            session.finalize_handshake().unwrap();
            session.close();
        }));

        // wait for spawned threads to exit
        for t in threads {
            let _ = t.join();
        }
    }

    #[test]
    fn reader_writer_thread_test() {
        let mut threads = vec![];
        let server_addr = "127.0.0.1:8001";
        let client_secret = StaticSecret::new(OsRng);
        let server_secret = StaticSecret::new(OsRng);

        let mut client_map = HashMap::new();
        client_map.insert(PublicKey::from(&client_secret), true);
        let provider_auth = ProviderAuthenticatorState {
            mix_map: HashMap::default(),
            client_map: client_map,
            from_client: false,
            from_mix: false,
        };
        let provider_authenticator = PeerAuthenticator::Provider(provider_auth);
        let client_auth = ClientAuthenticatorState{
            peer_public_key: PublicKey::from(&server_secret),
        };
        let client_authenticator = PeerAuthenticator::Client(client_auth);

        let server_keypair_clone = server_secret.clone();

        // server listener
        threads.push(thread::spawn(move|| {
            let listener = TcpListener::bind(server_addr.clone()).expect("could not start server");

            // server
            let server_config = SessionConfig {
                authenticator: provider_authenticator,
                authentication_key: server_secret,
                peer_public_key: None,
                additional_data: vec![],
            };
            let mut session = Session::new(server_config, false).unwrap();

            for connection in listener.incoming() {
                match connection {
                    Ok(stream) => {
                        session.initialize(stream).unwrap();
                        session = session.into_transport_mode().unwrap();
                        session.finalize_handshake().unwrap();

                        let mut reader_session = session.clone();
                        let mut session_threads = vec![];
                        session_threads.push(thread::spawn(move|| {
                            loop {
                                if let Ok(cmd) = reader_session.recv_command() {
                                    println!("server received command {:?}", cmd);
                                } else {
                                    reader_session.close();
                                    return
                                }
                            }
                        }));
                        session_threads.push(thread::spawn(move|| {
                            loop {
                                let cmd = Command::NoOp{};
                                match session.send_command(&cmd) {
                                    Ok(_) => {},
                                    Err(_) => return,
                                }
                                thread::sleep(time::Duration::from_secs(2));
                            }
                        }));
                        for t in session_threads {
                            let _ = t.join();
                        }
                        // XXX
                        //session.close();
                        return
                    }
                    Err(e) => { println!("connection failed {}", e); }
                }
            }
        }));

        // client dialer
        threads.push(thread::spawn(move|| {
            thread::sleep(Duration::from_secs(1));
            // client
            let client_config = SessionConfig {
                authenticator: client_authenticator,
                authentication_key: client_secret,
                peer_public_key: Some(PublicKey::from(&server_keypair_clone)),
                additional_data: vec![],
            };
            let mut session = Session::new(client_config, true).unwrap();

            let stream = TcpStream::connect(server_addr.clone()).expect("connection failed");
            session.initialize(stream).unwrap();
            session = session.into_transport_mode().unwrap();
            session.finalize_handshake().unwrap();

            let mut acc = 0;
            loop {
                match session.recv_command() {
                    Ok(_cmd) => {
                        if acc == 3 {
                            session.close();
                            return
                        }
                        session.send_command(&Command::NoOp{}).unwrap();
                        acc += 1;
                    },
                    Err(e) => println!("client receive command err: {}", e),
                }
            }
        }));

        // wait for spawned threads to exit
        for t in threads {
            let _ = t.join();
        }
    }
}
