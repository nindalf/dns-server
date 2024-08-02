use crate::error::ParseError;

pub(crate) struct DnsQuestion {
    pub(crate) qname: QuestionName,
    pub(crate) qtype: QuestionType,
    pub(crate) qclass: QuestionClass,
}

pub(crate) struct QuestionName(String);

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u16)]
pub(crate) enum QuestionType {
    A = 1,      // a host address
    Ns = 2,     // an authoritative name server
    Md = 3,     // a mail destination (Obsolete - use MX)
    Mf = 4,     // a mail forwarder (Obsolete - use MX)
    Cname = 5,  // the canonical name for an alias
    Soa = 6,    // marks the start of a zone of authority
    Mb = 7,     // a mailbox domain name (EXPERIMENTAL)
    Mg = 8,     // a mail group member (EXPERIMENTAL)
    Mr = 9,     // a mail rename domain name (EXPERIMENTAL)
    Null = 10,  // a null RR (EXPERIMENTAL)
    Wks = 11,   // a well known service description
    Ptr = 12,   // a domain name pointer
    Hinfo = 13, // host information
    Minfo = 14, // mailbox or mail list information
    Mx = 15,    // mail exchange
    Txt = 16,   // text strings
}

#[derive(PartialEq, Debug, Clone, Copy)]
#[repr(u16)]
pub(crate) enum QuestionClass {
    In = 1, // the Internet
    Cs = 2, // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    Ch = 3, // the CHAOS class
    Hs = 4, // Hesiod [Dyer 87]
}

impl TryFrom<&[u8]> for DnsQuestion {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let qname = QuestionName::try_from(value)?;

        let value = &value[qname.0.len() + 2..];
        let qtype: u16 = ((value[0] as u16) << 8) | value[1] as u16;
        let qtype = QuestionType::try_from(qtype)?;
        let qclass: u16 = ((value[2] as u16) << 8) | value[3] as u16;
        let qclass = QuestionClass::try_from(qclass)?;

        Ok(DnsQuestion {
            qname,
            qtype,
            qclass,
        })
    }
}

impl DnsQuestion {
    pub(crate) fn len(&self) -> usize {
        self.qname.0.len() + 2 + 2
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.qname.to_bytes());
        bytes.push((self.qtype as u16 >> 8) as u8);
        bytes.push(self.qtype as u8);
        bytes.push((self.qclass as u16 >> 8) as u8);
        bytes.push(self.qclass as u8);
        bytes
    }
}

impl TryFrom<&[u8]> for QuestionName {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let mut name = String::new();
        let mut value = value;

        if value.is_empty() {
            return Ok(QuestionName(name));
        }

        loop {
            let len = value[0] as usize;
            if len == 0 {
                break;
            }

            if !name.is_empty() {
                name.push('.');
            }

            name.push_str(&String::from_utf8_lossy(&value[1..=len]));
            value = &value[len + 1..];
        }
        Ok(QuestionName(name))
    }
}

impl QuestionName {
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        for part in self.0.split('.') {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
        bytes.push(0);
        bytes
    }
}

impl TryFrom<u16> for QuestionType {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(QuestionType::A),
            2 => Ok(QuestionType::Ns),
            3 => Ok(QuestionType::Md),
            4 => Ok(QuestionType::Mf),
            5 => Ok(QuestionType::Cname),
            6 => Ok(QuestionType::Soa),
            7 => Ok(QuestionType::Mb),
            8 => Ok(QuestionType::Mg),
            9 => Ok(QuestionType::Mr),
            10 => Ok(QuestionType::Null),
            11 => Ok(QuestionType::Wks),
            12 => Ok(QuestionType::Ptr),
            13 => Ok(QuestionType::Hinfo),
            14 => Ok(QuestionType::Minfo),
            15 => Ok(QuestionType::Mx),
            16 => Ok(QuestionType::Txt),
            _ => Err(ParseError::InvalidValue(value as u8)),
        }
    }
}

impl TryFrom<u16> for QuestionClass {
    type Error = ParseError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(QuestionClass::In),
            2 => Ok(QuestionClass::Cs),
            3 => Ok(QuestionClass::Ch),
            4 => Ok(QuestionClass::Hs),
            _ => Err(ParseError::InvalidValue(value as u8)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::QuestionName;
    use std::convert::TryFrom;

    #[test]
    fn test_question_name_try_from() {
        let test_cases: Vec<(&[u8], &str)> = vec![
            (b"\x07example\x03com\x00", "example.com"),
            (b"\x03sub\x07example\x03com\x00", "sub.example.com"),
            (b"\x01a\x02co\x00", "a.co"),
            // (b"\x0cxn--d1acufc\x08xn--p1ai\x00", "xn--d1acufc.xn--p1ai"),
            (
                b"\x04this\x02is\x01a\x04very\x04long\x06domain\x04name\x03com\x00",
                "this.is.a.very.long.domain.name.com",
            ),
            (b"\x03123\x07numbers\x03com\x00", "123.numbers.com"),
            // (b"\x00", "."),
        ];
        for (bytes, expected) in test_cases {
            let name = QuestionName::try_from(bytes).unwrap();
            assert_eq!(name.0, expected);
        }
    }
}
