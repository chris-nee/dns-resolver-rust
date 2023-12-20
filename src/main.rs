// Uncomment this block to pass the first stage
use nom::AsBytes;
use std::net::UdpSocket;

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

// DNS Question
pub struct DnsQuestion {
    domain_name: String,
    query_type: u16,
    query_class: u16,
}

impl DnsQuestion {
    pub fn new(domain_name: String, query_type: u16, query_class: u16) -> Self {
        Self {
            domain_name,
            query_type,
            query_class,
        }
    }

    fn encode_domain_name(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        self.domain_name.split('.').for_each(|x| {
            bytes.extend((x.len() as u8).to_be_bytes());
            bytes.extend(x.as_bytes());
        });

        bytes.push(0u8);
        bytes
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.encode_domain_name());
        // bytes.extend(self.query_type.to_be_bytes());
        bytes.push((self.query_type >> 8) as u8);
        bytes.push(self.query_type as u8);
        bytes.push((self.query_class >> 8) as u8);
        bytes.push(self.query_class as u8);
        // bytes.extend(self.query_class.to_be_bytes());

        bytes
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

                let mut response = Vec::new();

                let header = DnsHeader::new(1234, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0);
                response.extend(header.encode().into_iter());

                let question = DnsQuestion::new("codecrafters.io".to_string(), 1, 1);
                response.extend(question.encode().into_iter());

                udp_socket
                    .send_to(response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
