use rand::Rng;
use std::{env, net::UdpSocket};

#[derive(Default, Clone, Debug)]
struct DNSAnswer {
    name: String,
    field_type: u16,
    class: u16,
    ttl: u32,
    rd_len: u16,
    rdata: Vec<u8>,
}

impl DNSAnswer {
    fn from_bytes(byte_arr: &Vec<u8>, offset: usize) -> Self {
        if offset + 5 >= byte_arr.len() {
            return Self {
                name: String::new(),
                field_type: 1,
                class: 1,
                ttl: 60,
                rd_len: 4,
                rdata: vec![8, 8, 8, 8],
            };
        }

        let mut idx: usize = offset;
        let mut str_item: Vec<u8> = Vec::<u8>::new();

        while idx < byte_arr.len() {
            if byte_arr[idx] as u8 == 0 {
                if str_item.len() == 0 {
                    idx += 1;
                    break;
                }

                str_item.pop(); // remove the last "."
                idx += 1;
                break;
            }

            let msg_type = ((byte_arr[idx] as u8) >> 6) & 0b00000011;
            if msg_type == 3 {
                // compressed
                let mut idx_offset: usize =
                    u16::from_be_bytes([byte_arr[idx], byte_arr[idx + 1]]) as usize;

                idx_offset &= 0b0011111111111111;
                let label_len: usize = byte_arr[idx_offset] as usize;
                str_item.extend_from_slice(&byte_arr[idx_offset + 1..idx_offset + 1 + label_len]);
                str_item.push(46); // "."
                idx = idx_offset + label_len + 1;
            } else if msg_type == 0 {
                let label_len = byte_arr[idx] as usize;
                str_item.extend_from_slice(&byte_arr[idx + 1..idx + 1 + label_len]);

                str_item.push(46); // "."
                idx += label_len + 1;
            }
        }

        Self {
            name: String::from_utf8(str_item.clone()).unwrap(),
            field_type: u16::from_be_bytes([byte_arr[idx], byte_arr[idx + 1]]),
            class: u16::from_be_bytes([byte_arr[idx + 2], byte_arr[idx + 3]]),
            ttl: u32::from_be_bytes([
                byte_arr[idx + 4],
                byte_arr[idx + 5],
                byte_arr[idx + 6],
                byte_arr[idx + 7],
            ]),
            rd_len: u16::from_be_bytes([byte_arr[idx + 8], byte_arr[idx + 9]]),
            rdata: vec![
                byte_arr[idx + 10],
                byte_arr[idx + 11],
                byte_arr[idx + 12],
                byte_arr[idx + 13],
            ],
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

#[derive(Default, Clone, Debug)]
struct DNSQuestion {
    domain_name: String,
    query_type: u16,
    query_class: u16,
}
impl DNSQuestion {
    pub fn from_bytes(byte_arr: &Vec<u8>, offset: usize) -> Self {
        if offset + 5 > byte_arr.len() {
            return Self {
                domain_name: String::new(),
                query_type: 1,
                query_class: 1,
            };
        }
        let mut idx: usize = offset;
        let mut str_item: Vec<u8> = Vec::<u8>::new();

        while idx < byte_arr.len() {
            if byte_arr[idx] as u8 == 0 {
                if str_item.len() == 0 {
                    idx += 1;
                    break;
                }

                str_item.pop(); // remove the last "."
                idx += 1;
                break;
            }

            let msg_type = ((byte_arr[idx] as u8) >> 6) & 0b00000011;
            if msg_type == 3 {
                // compressed
                let mut idx_offset: usize =
                    u16::from_be_bytes([byte_arr[idx], byte_arr[idx + 1]]) as usize;
                idx_offset &= 0b0011111111111111;
                let label_len: usize = byte_arr[idx_offset] as usize;
                str_item.extend_from_slice(&byte_arr[idx_offset + 1..idx_offset + 1 + label_len]);
                str_item.push(46); // "."
                idx = idx_offset + label_len + 1;
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

#[derive(Default, Clone, Debug)]
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
    fn new() -> Self {
        let mut rng = rand::thread_rng();

        Self {
            id: rng.gen::<u16>(),
            qr: 0,
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
        let qd_count = u16::from_be_bytes([byte_arr[offset + 4], byte_arr[offset + 5]]);
        let an_count = u16::from_be_bytes([byte_arr[offset + 6], byte_arr[offset + 7]]);
        let rs_count = u16::from_be_bytes([byte_arr[offset + 8], byte_arr[offset + 9]]);
        let ar_count = u16::from_be_bytes([byte_arr[offset + 10], byte_arr[offset + 11]]);

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
    let args: Vec<String> = env::args().collect();
    let resolver = args[2].clone();

    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    // Uncomment this block to pass the first stage
    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let udp_socket_2 = UdpSocket::bind("127.0.0.1:0").expect("Failed to bind to address");
    let mut buf = [0; 1024];

    const HEADER_SIZE: usize = 12; // bytes

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                let mut byte_arr: Vec<u8> = Vec::new();
                byte_arr.extend_from_slice(&buf);

                println!("Received {} bytes from {}", size, source);

                let mut response = Vec::new();

                let mut header = DNSHeader::from_bytes(&byte_arr, 0);
                header.qr = 1;
                header.an_count = header.qd_count;
                if header.opcode != 0 {
                    header.r_code = 4;
                }
                response.extend(header.to_bytes());

                let mut question_packets: Vec<DNSQuestion> = Vec::new();
                let mut answer_packets: Vec<DNSAnswer> = Vec::new();

                let mut q_offset = HEADER_SIZE;
                for _ in 0..header.qd_count {
                    let question = DNSQuestion::from_bytes(&byte_arr, q_offset);
                    q_offset += question.to_bytes().len();

                    // Forward to dns server
                    let mut query = Vec::new();
                    let mut inner_header = DNSHeader::new();
                    inner_header.qd_count = 1;

                    let clone_question = question.clone();

                    query.extend(inner_header.to_bytes());
                    query.extend(clone_question.to_bytes());

                    udp_socket_2
                        .send_to(&query, &resolver.clone())
                        .expect("Unable to send to resolver");

                    let mut recv_buf: [u8; 1024] = [0; 1024];
                    let (size, _) = udp_socket_2
                        .recv_from(&mut recv_buf)
                        .expect("Unable to receive");

                    let mut recv_buf_vec = Vec::new();
                    recv_buf_vec.extend_from_slice(&recv_buf[..size]);

                    let new_header = DNSHeader::from_bytes(&recv_buf_vec, 0);

                    let mut inner_offset = HEADER_SIZE;
                    for _ in 0..new_header.qd_count {
                        let new_qn = DNSQuestion::from_bytes(&recv_buf_vec, inner_offset);
                        inner_offset += new_qn.to_bytes().len();
                        question_packets.push(new_qn);

                        let new_ans = DNSAnswer::from_bytes(&recv_buf_vec, inner_offset);
                        answer_packets.push(new_ans);
                    }
                }

                for question in question_packets {
                    response.extend(question.to_bytes());
                }

                for answer in answer_packets {
                    response.extend(answer.to_bytes());
                }

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
