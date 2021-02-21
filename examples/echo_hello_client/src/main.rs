
#[macro_use]
extern crate arrayref;

//extern crate rand;
extern crate rustc_serialize;
extern crate x25519_dalek_ng;
extern crate mix_link;

use std::net::TcpStream;
//use rand::os::OsRng;
//use rustc_serialize::hex::{FromHex, ToHex};
use rustc_serialize::hex::FromHex;

use x25519_dalek_ng::{PublicKey, StaticSecret};
use mix_link::sync::{Session};
use mix_link::messages::{SessionConfig, PeerAuthenticator, ClientAuthenticatorState};
use mix_link::commands::{Command};


fn main() {
    let server_addr = "127.0.0.1:36669";

    /*
    let mut rng = OsRng::new().expect("failure to create an OS RNG");
    let client_keypair = PrivateKey::generate(&mut rng).unwrap();
    println!("private_key: {}\n", client_keypair.to_vec().to_hex());
    return;
     */

    let private_key_bytes = "7136a09854d112beb513dcd892af8789e277925386c44f7f85f29e98deb14eda".from_hex().unwrap();
    let private_key = StaticSecret::from(*array_ref![private_key_bytes, 0, 32]);
    //println!("public_key: {}\n", private_key.public_key().to_vec().to_hex());
    // public key is c8de601616d781d8e26589cc78399541ed9a89ef1fa7013a3c930a5b4da10f06


    let server_public_key_bytes = "48887bd92bfee3ea74d99aa0d489bea1b32f4e923ccf240ac5949d3ab3f23e12".from_hex().unwrap();

    
    let server_public_key = PublicKey::from(*array_ref![server_public_key_bytes, 0, 32]);
    let client_auth = ClientAuthenticatorState{
        peer_public_key: server_public_key.clone(),
    };
    let client_authenticator = PeerAuthenticator::Client(client_auth);
    
    let client_config = SessionConfig {
        authenticator: client_authenticator,
        authentication_key: private_key,
        peer_public_key: Some(server_public_key),
        additional_data: vec![],
    };
    let mut session = Session::new(client_config, true).unwrap();
    let stream = TcpStream::connect(server_addr.clone()).expect("connection failed");

    println!("connected to server");
    
    session.initialize(stream).unwrap();

    println!("handshake completed");
    
    session = session.into_transport_mode().unwrap();
    session.finalize_handshake().unwrap();


    
    let cmd = Command::MessageEmpty {
        sequence: 1234567,
    };
    session.send_command(&cmd).unwrap();

    println!("MessageEmpty command sent, awaiting reply");
    
    let received_cmd = session.recv_command().unwrap();
    assert_eq!(cmd, received_cmd);

    println!("success!");
}
