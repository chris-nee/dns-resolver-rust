use std::net::UdpSocket;
struct DNSQuestion {
    domain_name: String,
    query_type: u16,
    query_class: u16,
}
impl DNSQuestion {
    fn new(domain_name: String, query_type: u16, query_class: u16) -> Self {
        Self {
            domain_name,
            query_type,
            query_class,
        }
    }
    fn encoded_domain_name(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.domain_name.split(".") {
            bytes.extend((part.len() as u8).to_be_bytes());
            bytes.extend(part.as_bytes())
        }
        bytes.push(0);
        bytes
    }
    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(self.encoded_domain_name());
        bytes.extend(self.query_type.to_be_bytes());
        bytes.extend(self.query_class.to_be_bytes());
        bytes
    }
}
struct DNSHeader {
    id: u16,
    qr: u8,
    opcode: u8,
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    z: u8,
    r_code: u8,
    qd_count: u16,
    an_count: u16,
    rs_count: u16,
    ar_count: u16,
}
impl Default for DNSHeader {
    fn default() -> Self {
        DNSHeader {
            id: 1234,
            qr: 1,
            opcode: 0,
            aa: 0,
            tc: 0,
            rd: 0,
            ra: 0,
            z: 0,
            r_code: 0,
            qd_count: 0,
            an_count: 0,
            rs_count: 0,
            ar_count: 0,
        }
    }
}
impl DNSHeader {
    // To big-endian bytes
    fn to_be_bytes(&self) -> [u8; 12] {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend(&self.id.to_be_bytes());
        bytes.push((self.qr << 7) | (self.opcode << 3) | (self.aa << 2) | (self.tc << 1) | self.rd);
        bytes.push((self.ra << 7) | (self.z << 4) | (self.r_code));
        bytes.extend(&self.qd_count.to_be_bytes());
        bytes.extend(&self.an_count.to_be_bytes());
        bytes.extend(&self.rs_count.to_be_bytes());
        bytes.extend(&self.ar_count.to_be_bytes());
        bytes
            .try_into()
            .expect("DNSHeader did not match expected length")
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
                let mut header = DNSHeader::default();
                header.qd_count = 1;
                let question = DNSQuestion::new("codecrafters.io".to_string(), 1, 1);
                let mut response = Vec::new();
                response.extend(header.to_be_bytes());

                response.extend(question.to_be_bytes());
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
