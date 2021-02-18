// lib.rs - noise based wire protocol for building mix networks
// Copyright (C) 2018  David Anthony Stainton.
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

//!
//! This crate provides a post-quantum Noise Protocol Framework based
//! cryptographic wire protocol for constructing mix networks. The main
//! intention of this protocol is to interoperate with the Katzenpost wire
//! protocol. That is, this crate could be used in the composition of a
//! Rust client for the Katzenpost decryption mix network.
//!

extern crate snow;
extern crate byteorder;
extern crate subtle;
extern crate x25519_dalek_ng;
extern crate sphinxcrypto;

pub mod errors;
pub mod constants;
pub mod commands;
pub mod messages;
pub mod sync;


#[cfg(test)]
mod tests {

    extern crate rand_core;
    extern crate snow;

    use snow::Builder;
    use snow::params::NoiseParams;
    use self::rand_core::OsRng;

    use x25519_dalek_ng::{PublicKey, StaticSecret};

    #[test]
    fn noise_test() {
        let noise_params: NoiseParams = "Noise_XX_25519_ChaChaPoly_BLAKE2b".parse().unwrap();
        let prologue = [0u8;1];

        // server
        let server_secret = StaticSecret::new(OsRng);
        let server_builder: Builder = Builder::new(noise_params.clone());
        let mut server_handshake_state = server_builder
            .local_private_key(&server_secret.to_bytes())
            .prologue(&prologue)
            .build_responder().unwrap();
        let mut server_in = [0u8; 65535];
        let mut server_out = [0u8; 65535];

        // client
        let client_secret = StaticSecret::new(OsRng);
        let client_builder: Builder = Builder::new(noise_params.clone());

        let mut client_handshake_state = client_builder
            .local_private_key(&client_secret.to_bytes())
            .remote_public_key(&PublicKey::from(&server_secret).to_bytes())
            .prologue(&prologue)
            .build_initiator().unwrap();
        let mut client_out = [0u8; 65535];
        let mut client_in = [0u8; 65535];

        // handshake
        let mut _client_len = client_handshake_state.write_message(&[0u8; 0], &mut client_out).unwrap();
        let mut _server_len = server_handshake_state.read_message(&client_out[.._client_len], &mut server_in).unwrap();

        _server_len = server_handshake_state.write_message(&[0u8; 0], &mut server_out).unwrap();
        _client_len = client_handshake_state.read_message(&server_out[.._server_len], &mut client_in).unwrap();

        _client_len = client_handshake_state.write_message(&[], &mut client_out).unwrap();
        server_handshake_state.read_message(&client_out[.._client_len], &mut server_in).unwrap();

        // data transfer
        let mut client_transfer_state = client_handshake_state.into_transport_mode().unwrap();
        let mut server_transfer_state = server_handshake_state.into_transport_mode().unwrap();

        // server talks to client
        let server_banner = b"yo";
        _server_len = server_transfer_state.write_message(server_banner, &mut server_out).unwrap();
        client_transfer_state.read_message(&server_out[.._server_len], &mut client_in).unwrap();
        assert_eq!(&client_in[..server_banner.len()], server_banner);

        // client talks to server
        let client_response = b"ho";
        _client_len = client_transfer_state.write_message(client_response, &mut client_out).unwrap();
        server_transfer_state.read_message(&client_out[.._client_len], &mut server_in).unwrap();
        assert_eq!(client_response, &server_in[..client_response.len()]);
    }
}
