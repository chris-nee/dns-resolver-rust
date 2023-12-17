// Uncomment this block to pass the first stage
use std::net::UdpSocket;
use std::str;

// DNS Header
pub struct DnsHeader {
    bytes: [u8; 12],
}

impl DnsHeader {
    pub fn new(
        id: u16,
        qr: u8,
        opcode: u8,
        aa: u8,
        tc: u8,
        rd: u8,
        ra: u8,
        z: u8,
        rcode: u8,
        qdcount: u16,
        ancount: u16,
        nscount: u16,
        arcount: u16,
    ) -> Self {
        let bytes = [
            (id >> 8) as u8,
            id as u8,
            qr << 7 | opcode << 3 | aa << 2 | tc << 1 | rd,
            ra << 7 | z << 4 | rcode,
            qdcount as u8,
            (qdcount >> 8) as u8,
            ancount as u8,
            (ancount >> 8) as u8,
            nscount as u8,
            (nscount >> 8) as u8,
            arcount as u8,
            (arcount >> 8) as u8,
        ];

        Self { bytes }
    }

    pub fn encode(&self) -> &[u8] {
        &self.bytes //.as_bytes()
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let _received_data = String::from_utf8_lossy(&buf[0..size]);
                println!("Received {} bytes from {}", size, source);
                println!("Received data: {:?}", &buf[..size]);

                // Simply for printing
                match str::from_utf8(&buf[0..size]) {
                    Ok(received_str) => {
                        println!("parsed: {}", received_str)
                    }
                    Err(_e) => {
                        println!("Err parsing utf8")
                    }
                };

                let header = DnsHeader::new(1234, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
                let response = header.bytes; // .encode();

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
