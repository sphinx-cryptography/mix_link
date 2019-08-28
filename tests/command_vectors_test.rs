// command_vectors_test.rs - vector tests for wire commands
// Copyright (C) 2019  David Anthony Stainton.
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


#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate hex;

extern crate sphinxcrypto;
extern crate mix_link;

use std::fs::File;
use std::io::Read;

use mix_link::commands::{Command};

use sphinxcrypto::constants::SURB_ID_SIZE;



#[derive(Deserialize, Debug)]
#[allow(non_snake_case)]
struct WireCommandsTest {
    NoOp: String,
    Disconnect: String,
    SendPacketPayload: String,
    SendPacket: String,
    RetrieveMessageSeq: u32,
    RetrieveMessage: String,
    MessageEmpty: String,
    MessageEmptySeq: u32,
    Message: String,
    MessageHint: u8,
    MessageSeq: u32,
    MessagePayload: String,
    MessageAck: String,
    MessageAckHint: u8,
    MessageAckSeq: u32,
    MessageAckPayload: String,
    GetConsensus: String,
    GetConsensusEpoch: u64,
    Consensus: String,
    ConsensusPayload: String,
    ConsensusErrorCode: u8,
}

#[test]
fn command_vector_test() {
    let mut file = File::open("wire_commands_vectors.json").unwrap();
    let mut vectors = String::new();
    file.read_to_string(&mut vectors).unwrap();
    let tests: WireCommandsTest = serde_json::from_str(&vectors).unwrap();

    let expected_no_op_bytes = hex::decode(tests.NoOp).unwrap();
    let no_op = Command::NoOp{};
    let no_op_bytes = no_op.clone().to_vec();
    assert_eq!(expected_no_op_bytes, no_op_bytes);

    let cmd = Command::from_bytes(&expected_no_op_bytes).unwrap();
    match cmd {
        Command::NoOp{} => {
        },
        _ => {
            panic!("not a NoOp command");
        }
    }

    let disconnect_bytes = hex::decode(tests.Disconnect).unwrap();
    let cmd = Command::from_bytes(&disconnect_bytes).unwrap();
    match cmd {
        Command::Disconnect{} => {
        },
        _ => {
            panic!("not a Disconnect command");
        }
    }

    let send_packet_payload_bytes = hex::decode(tests.SendPacketPayload).unwrap();
    let want_send_packet_bytes = hex::decode(tests.SendPacket).unwrap();
    let send_packet = Command::SendPacket{
        sphinx_packet: send_packet_payload_bytes,
    };
    let send_packet_bytes = send_packet.to_vec();
    assert_eq!(send_packet_bytes, want_send_packet_bytes);

    let retrieve_message = Command::RetrieveMessage{
        sequence: tests.RetrieveMessageSeq,
    };
    let retrieve_message_bytes = retrieve_message.to_vec();
    let want_retrieve_message_bytes = hex::decode(tests.RetrieveMessage).unwrap();
    assert_eq!(retrieve_message_bytes, want_retrieve_message_bytes);

    let want_message_empty = hex::decode(tests.MessageEmpty).unwrap();
    let empty_message = Command::MessageEmpty{
        sequence: tests.MessageEmptySeq,
    };
    let empty_message_bytes = empty_message.to_vec();
    assert_eq!(want_message_empty, empty_message_bytes);

    let want_message_bytes = hex::decode(tests.Message).unwrap();
    let payload = hex::decode(tests.MessagePayload).unwrap();
    let message = Command::MessageMessage{
        queue_size_hint: tests.MessageHint,
        sequence: tests.MessageSeq,
        payload: payload,
    };
    let message_bytes = message.to_vec();
    assert_eq!(message_bytes, want_message_bytes);

    let message_ack_want = hex::decode(tests.MessageAck).unwrap();
    let ack_payload = hex::decode(tests.MessageAckPayload).unwrap();
    let message_ack = Command::MessageAck{
        queue_size_hint: tests.MessageAckHint,
        sequence: tests.MessageAckSeq,
        payload: ack_payload,
        id: [0u8; SURB_ID_SIZE],
    };
    let message_ack_bytes = message_ack.to_vec();
    assert_eq!(message_ack_want, message_ack_bytes);

    let want_get_consensus = hex::decode(tests.GetConsensus).unwrap();
    let get_consensus = Command::GetConsensus{
        epoch: tests.GetConsensusEpoch,
    };
    let get_consensus_bytes = get_consensus.to_vec();
    assert_eq!(want_get_consensus, get_consensus_bytes);

    let want_consensus = hex::decode(tests.Consensus).unwrap();
    let consensus_payload = hex::decode(tests.ConsensusPayload).unwrap();
    let consensus = Command::Consensus{
        payload: consensus_payload,
        error_code: tests.ConsensusErrorCode,
    };
    let consensus_bytes = consensus.to_vec();
    assert_eq!(consensus_bytes, want_consensus);
}
