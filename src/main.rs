mod answer;
mod common;
mod error;
mod header;
mod packet;
mod question;

use std::net::UdpSocket;

fn main() {
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let received = &buf[..size];
                let mut packet = packet::DnsPacket::try_from(received).unwrap();
                packet.header.flip_qr();
                packet.header.qdcount = packet.questions.len() as u16;
                let answer = answer::DnsAnswer::new(
                    "codecrafters.io".into(),
                    common::DnsType::A,
                    common::DnsClass::In,
                    60,
                    answer::RData::A([8, 8, 8, 8]),
                );
                packet.add_answer(answer);
                let response = packet.to_bytes();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
