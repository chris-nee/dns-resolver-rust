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

    fn to_bytes(&self) -> Vec<u8> {
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
    pub fn from_bytes(byte_arr: &Vec<u8>, offset: usize) -> Self {
        if offset + 5 >= byte_arr.len() {
            return Self {
                domain_name: String::new(),
                query_type: 1,
                query_class: 1,
            };
        }

        let mut idx: usize = offset;
        let mut str_item: Vec<u8> = Vec::<u8>::new();

        while idx < byte_arr.len() {
            println!("THE LEN {}", str_item.len());
            if byte_arr[idx] as u8 == 0 {
                if str_item.len() == 0 {
                    break;
                }
                str_item.pop(); // remove the last "."
                idx += 5;
                continue;
            }

            let msg_type = ((byte_arr[idx] as u8) >> 6) & 0b00000011;
            if msg_type == 3 {
                // compressed
                let mut idx_offset: usize =
                    u16::from_be_bytes([byte_arr[idx], byte_arr[idx + 1]]) as usize;

                idx_offset &= 0b0011111111111111;
                // idx_offset -= 12; // account for header
                let label_len: usize = byte_arr[idx_offset] as usize;
                str_item.extend_from_slice(&byte_arr[idx_offset + 1..idx_offset + 1 + label_len]);
                str_item.push(46); // "."
                idx += 1;
            } else if msg_type == 0 {
                let label_len = byte_arr[idx] as usize;
                str_item.extend_from_slice(&byte_arr[idx + 1..idx + 1 + label_len]);

                str_item.push(46); // "."
                idx += label_len + 1;
            }
        }

        Self {
            domain_name: String::from_utf8(str_item.clone()).unwrap(),
            query_type: byte_arr[idx] as u16 | byte_arr[idx + 1] as u16,
            query_class: byte_arr[idx + 2] as u16 | byte_arr[idx + 3] as u16,
        }
    }

    fn to_bytes(&self) -> Vec<u8> {
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
    fn from_bytes(byte_arr: &Vec<u8>, offset: usize) -> Self {
        let id = (byte_arr[offset + 0] as u16) << 8 | byte_arr[offset + 1] as u16;
        let qr = (byte_arr[offset + 2] as u8 & ((0b00000001) << 7)) >> 7;
        let opcode = (byte_arr[offset + 2] as u8 & ((0b00001111) << 3)) >> 3;
        let aa = (byte_arr[offset + 2] as u8 & ((0b00000001) << 2)) >> 2;
        let tc = (byte_arr[offset + 2] as u8 & ((0b00000001) << 1)) >> 1;
        let rd = byte_arr[offset + 2] as u8 & (0b00000001);
        let ra = (byte_arr[offset + 3] as u8 & ((0b00000001) << 7)) >> 7;
        let z = (byte_arr[offset + 3] as u8 & ((0b00000111) << 4)) >> 4;
        let r_code = byte_arr[offset + 3] as u8 & (0b00001111);
        let qd_count = (byte_arr[offset + 4] as u16) << 8 | byte_arr[offset + 5] as u16;
        let an_count = (byte_arr[offset + 6] as u16) << 8 | byte_arr[offset + 7] as u16;
        let rs_count = (byte_arr[offset + 8] as u16) << 8 | byte_arr[offset + 9] as u16;
        let ar_count = (byte_arr[offset + 10] as u16) << 8 | byte_arr[offset + 11] as u16;

        Self {
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

    // To big-endian bytes
    fn to_bytes(&self) -> [u8; 12] {
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

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    const HEADER_SIZE: usize = 12; // bytes

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                // let _received_data = String::from_utf8_lossy(&buf[0..size]);
                let mut byte_arr: Vec<u8> = Vec::new();
                byte_arr.extend_from_slice(&buf);

                println!("Received {} bytes from {}", size, source);

                let mut header = DNSHeader::from_bytes(&byte_arr, 0);
                header.qr = 1;
                // header.an_count = 1;
                if header.opcode != 0 {
                    header.r_code = 4;
                }

                let question = DNSQuestion::from_bytes(&byte_arr, HEADER_SIZE);

                let answer =
                    DNSAnswer::new(question.domain_name.clone(), 1, 1, 60, 4, vec![8, 8, 8, 8]);

                let mut response = Vec::new();

                response.extend(header.to_bytes());
                response.extend(question.to_bytes());
                response.extend(answer.to_bytes());

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
