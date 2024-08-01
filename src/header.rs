use crate::error::ParseError;

#[derive(PartialEq, Debug)]
pub(crate) struct DnsHeader {
    pub id: u16, // Packet Identifier (ID)	                16 bits	A random ID assigned to query packets. Response packets must reply with the same ID.
    pub qr: PacketType, // Query/Response Indicator (QR)    1 bit	1 for a response packet, 0 for a query packet.
    pub opcode: OpCode, // Operation Code (OPCODE)          4 bits	Specifies the kind of query in a message.
    pub aa: bool, // Authoritative Answer (AA)	            1 bit	1 if the responding server "owns" the domain queried, i.e., it's authoritative.
    pub tc: bool, // Truncation (TC)	                    1 bit	1 if the message is larger than 512 bytes. Always 0 in UDP responses.
    pub rd: bool, // Recursion Desired (RD)	                1 bit	Sender sets this to 1 if the server should recursively resolve this query, 0 otherwise.
    pub ra: bool, // Recursion Available (RA)	            1 bit	Server sets this to 1 to indicate that recursion is available.
    pub z: u8, // Reserved (Z)	                            3 bits	Used by DNSSEC queries. At inception, it was reserved for future use.
    pub rcode: ResponseCode, // Response Code (RCODE)	    4 bits	Response code indicating the status of the response.
    pub qdcount: u16, // Question Count (QDCOUNT)	        16 bits	Number of questions in the Question section. Expected value: 0.
    pub ancount: u16, // Answer Record Count (ANCOUNT)	    16 bits	Number of records in the Answer section. Expected value: 0.
    pub nscount: u16, // Authority Record Count (NSCOUNT)	16 bits	Number of records in the Authority section. Expected value: 0.
    pub arcount: u16, // Additional Record Count (ARCOUNT)	16 bits	Number of records in the Additional section. Expected value: 0.
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum PacketType {
    Query = 0,
    Response = 1,
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum OpCode {
    Query = 0,
    InverseQuery = 1,
    ServerStatus = 2,
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u8)]
pub(crate) enum ResponseCode {
    NoError = 0,
    FormatError = 1,
    ServFail = 2,
    NxDomain = 3,
}

impl DnsHeader {
    pub(crate) fn flip_qr(&mut self) {
        self.qr = match self.qr {
            PacketType::Query => PacketType::Response,
            PacketType::Response => PacketType::Query,
        };
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(12);
        bytes.extend(self.id.to_be_bytes());

        let flags = ((self.qr as u8) << 7)
            | (((self.opcode as u8) & 0x0F) << 3)
            | ((self.aa as u8) << 2)
            | ((self.tc as u8) << 1)
            | (self.rd as u8);
        bytes.push(flags);

        let rcode_flags =
            ((self.ra as u8) << 7) | ((self.z & 0x07) << 4) | ((self.rcode as u8) & 0x0F);
        bytes.push(rcode_flags);

        bytes.extend_from_slice(&self.qdcount.to_be_bytes());
        bytes.extend_from_slice(&self.ancount.to_be_bytes());
        bytes.extend_from_slice(&self.nscount.to_be_bytes());
        bytes.extend_from_slice(&self.arcount.to_be_bytes());
        bytes
    }
}

impl TryFrom<&[u8]> for DnsHeader {
    type Error = ParseError;

    fn try_from(bytes: &[u8]) -> Result<DnsHeader, Self::Error> {
        let id: u16 = (bytes[0] as u16) << 8 | bytes[1] as u16;

        let qr = PacketType::try_from(bytes[2] >> 7)?;
        let opcode = OpCode::try_from((bytes[2] << 1) >> 4)?;
        let aa = ((bytes[2] << 5) >> 7) != 0;
        let tc = ((bytes[2] << 6) >> 7) != 0;
        let rd = ((bytes[2] << 7) >> 7) != 0;

        let ra = (bytes[3] >> 7) != 0;
        let z = (bytes[3] << 1) >> 5;
        let rcode = ResponseCode::try_from((bytes[3] << 4) >> 4)?;

        let qdcount: u16 = (bytes[4] as u16) << 8 | bytes[5] as u16;
        let ancount: u16 = (bytes[6] as u16) << 8 | bytes[7] as u16;
        let nscount: u16 = (bytes[8] as u16) << 8 | bytes[9] as u16;
        let arcount: u16 = (bytes[10] as u16) << 8 | bytes[11] as u16;
        Ok(DnsHeader {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            z,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        })
    }
}

impl TryFrom<u8> for PacketType {
    type Error = ParseError;

    fn try_from(byte: u8) -> Result<PacketType, Self::Error> {
        match byte {
            0 => Ok(PacketType::Query),
            1 => Ok(PacketType::Response),
            _ => Err(ParseError::InvalidValue(byte)),
        }
    }
}

impl TryFrom<u8> for OpCode {
    type Error = ParseError;

    fn try_from(byte: u8) -> Result<OpCode, Self::Error> {
        match byte {
            0 => Ok(OpCode::Query),
            1 => Ok(OpCode::InverseQuery),
            2 => Ok(OpCode::ServerStatus),
            _ => Err(ParseError::InvalidValue(byte)),
        }
    }
}

impl TryFrom<u8> for ResponseCode {
    type Error = ParseError;

    fn try_from(byte: u8) -> Result<ResponseCode, Self::Error> {
        match byte {
            0 => Ok(ResponseCode::NoError),
            1 => Ok(ResponseCode::FormatError),
            2 => Ok(ResponseCode::ServFail),
            3 => Ok(ResponseCode::NxDomain),
            _ => Err(ParseError::InvalidValue(byte)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_parse_packet_type() {
        assert_eq!(PacketType::try_from(0), Ok(PacketType::Query));
        assert_eq!(PacketType::try_from(1), Ok(PacketType::Response));
        for i in 2..=7 {
            assert_eq!(PacketType::try_from(i), Err(ParseError::InvalidValue(i)));
        }
    }

    #[test]
    fn test_parse_opcode() {
        assert_eq!(OpCode::try_from(0), Ok(OpCode::Query));
        assert_eq!(OpCode::try_from(1), Ok(OpCode::InverseQuery));
        assert_eq!(OpCode::try_from(2), Ok(OpCode::ServerStatus));
        for i in 3..=7 {
            assert_eq!(OpCode::try_from(i), Err(ParseError::InvalidValue(i)));
        }
    }

    #[test]
    fn test_parse_response_code() {
        assert_eq!(ResponseCode::try_from(0), Ok(ResponseCode::NoError));
        assert_eq!(ResponseCode::try_from(1), Ok(ResponseCode::FormatError));
        assert_eq!(ResponseCode::try_from(2), Ok(ResponseCode::ServFail));
        assert_eq!(ResponseCode::try_from(3), Ok(ResponseCode::NxDomain));
        for i in 4..=15 {
            assert_eq!(ResponseCode::try_from(i), Err(ParseError::InvalidValue(i)));
        }
    }

    #[test]
    fn test_standard_query() {
        let standard_query = &[
            0x12, 0x34, // ID: 0x1234
            0x01, 0x00, // QR = 0 (query), Opcode = 0 (standard query), AA = 0, TC = 0, RD = 1
            0x00, 0x01, // QDCOUNT = 1 (one question)
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        let expected = DnsHeader {
            id: 0x1234,
            qr: PacketType::Query,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: false,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert_packet_equality(standard_query, expected);
    }

    #[test]
    fn test_standard_response() {
        let standard_response = &[
            0x56, 0x78, // ID: 0x5678
            0x81, 0x80, // QR = 1 (response), Opcode = 0, AA = 0, TC = 0, RD = 1, RA = 1
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        let expected = DnsHeader {
            id: 0x5678,
            qr: PacketType::Response,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        assert_packet_equality(standard_response, expected);
    }

    #[test]
    fn test_truncated_query() {
        let standard_query = &[
            0x9A, 0xBC, // ID: 0x9ABC
            0x02, 0x00, // QR = 0 (query), Opcode = 0, AA = 0, TC = 1, RD = 0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        let expected = DnsHeader {
            id: 0x9ABC,
            qr: PacketType::Query,
            opcode: OpCode::Query,
            aa: false,
            tc: true,
            rd: false,
            ra: false,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert_packet_equality(standard_query, expected);
    }

    #[test]
    fn test_authoritative_response_with_no_error() {
        let standard_response = &[
            0xDE, 0xF0, // ID: 0xDEF0
            0x84, 0x00, // QR = 1 (response), Opcode = 0, AA = 1, TC = 0, RD = 0, RA = 0
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x01, // ANCOUNT = 1
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        let expected = DnsHeader {
            id: 0xDEF0,
            qr: PacketType::Response,
            opcode: OpCode::Query,
            aa: true,
            tc: false,
            rd: false,
            ra: false,
            z: 0,
            rcode: ResponseCode::NoError,
            qdcount: 1,
            ancount: 1,
            nscount: 0,
            arcount: 0,
        };
        assert_packet_equality(standard_response, expected);
    }

    #[test]
    fn test_non_authoritative_response_with_name_error() {
        let standard_response = &[
            0xAB, 0xCD, // ID: 0xABCD
            0x81,
            0x83, // QR = 1 (response), Opcode = 0, AA = 0, TC = 0, RD = 1, RA = 1, RCODE = 3 (NXDOMAIN)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT = 0
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
        ];
        let expected = DnsHeader {
            id: 0xABCD,
            qr: PacketType::Response,
            opcode: OpCode::Query,
            aa: false,
            tc: false,
            rd: true,
            ra: true,
            z: 0,
            rcode: ResponseCode::NxDomain,
            qdcount: 1,
            ancount: 0,
            nscount: 0,
            arcount: 0,
        };
        assert_packet_equality(standard_response, expected);
    }

    fn assert_packet_equality(bytes: &[u8], expected: DnsHeader) {
        let actual = DnsHeader::try_from(bytes).unwrap();
        assert_eq!(actual, expected);
        let serialised = actual.to_bytes();
        assert_eq!(bytes, serialised.as_slice());
    }
}
