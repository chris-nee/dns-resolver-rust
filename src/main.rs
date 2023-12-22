use std::net::UdpSocket;

struct DNSAnswer {
    name: String,
    field_type: u16,
    class: u16,
    ttl: u32,
    rd_len: u16,
    rdata: Vec<u8>,
}

impl DNSAnswer {
    fn new(
        name: String,
        field_type: u16,
        class: u16,
        ttl: u32,
        rd_len: u16,
        rdata: Vec<u8>,
    ) -> Self {
        Self {
            name,
            field_type,
            class,
            ttl,
            rd_len,
            rdata,
        }
    }

    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        let parts = self.name.split(".");
        for part in parts {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0);

        bytes.extend(self.field_type.to_be_bytes());
        bytes.extend(self.class.to_be_bytes());
        bytes.extend(self.ttl.to_be_bytes());
        bytes.extend(self.rd_len.to_be_bytes());
        bytes.extend(self.rdata.iter());

        bytes
    }
}

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

    fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();

        let parts = self.domain_name.split(".");
        for part in parts {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0);

        bytes.extend_from_slice(&self.query_type.to_be_bytes());
        bytes.extend_from_slice(&self.query_class.to_be_bytes());

        bytes.try_into().expect("err")
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
impl DNSHeader {
    fn new(
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
    ) -> Self {
        DNSHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            r_code,
            qd_count,
            an_count,
            rs_count,
            ar_count,
        }
    }
}
impl DNSHeader {
    // To big-endian bytes
    fn to_be_bytes(&self) -> [u8; 12] {
        let mut bytes: Vec<u8> = Vec::new();

        bytes.extend(&self.id.to_be_bytes());
        bytes.push(&self.qr << 7 | &self.opcode << 3 | &self.aa << 2 | &self.tc << 1 | &self.rd);
        bytes.push(&self.ra << 7 | &self.z << 4 | &self.r_code);

        bytes.extend(&self.qd_count.to_be_bytes());
        bytes.extend(&self.an_count.to_be_bytes());
        bytes.extend(&self.rs_count.to_be_bytes());
        bytes.extend(&self.ar_count.to_be_bytes());

        bytes.try_into().expect("[u8; 12]")
    }
}

const HEADER_SIZE: usize = 12; // bytes

fn get_header_slice(src: &[u8]) -> [u8; HEADER_SIZE] {
    return src.try_into().expect("size of HEADER_SIZE");
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
                // let _received_data = String::from_utf8_lossy(&buf[0..size]);
                let _received_header: [u8; HEADER_SIZE] = get_header_slice(&buf);

                println!("Received {} bytes from {}", size, source);

                let header = DNSHeader::new(
                    (_received_header[0] as u16) << 8 | _received_header[1] as u16,
                    _received_header[2] as u8 & ((1 as u8) << 7),
                    _received_header[2] as u8 & ((15 as u8) << 3),
                    _received_header[2] as u8 & ((1 as u8) << 2),
                    _received_header[2] as u8 & ((1 as u8) << 1),
                    _received_header[2] as u8 & (1 as u8),
                    _received_header[3] as u8 & ((1 as u8) << 7),
                    _received_header[3] as u8 & ((7 as u8) << 4),
                    _received_header[3] as u8 & (15 as u8),
                    (_received_header[4] as u16) << 8 | _received_header[5] as u16,
                    (_received_header[6] as u16) << 8 | _received_header[7] as u16,
                    (_received_header[8] as u16) << 8 | _received_header[9] as u16,
                    (_received_header[10] as u16) << 8 | _received_header[11] as u16,
                );
                let question = DNSQuestion::new("codecrafters.io".to_string(), 1, 1);
                let answer =
                    DNSAnswer::new("codecrafters.io".to_string(), 1, 1, 60, 4, vec![8, 8, 8, 8]);

                let mut response = Vec::new();

                response.extend(header.to_be_bytes());
                response.extend(question.to_be_bytes());
                response.extend(answer.to_be_bytes());

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
