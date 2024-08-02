use crate::common::{DnsClass, DnsType, Name};
use crate::error::ParseError;

pub(crate) struct DnsQuestion {
    pub(crate) qname: Name,
    pub(crate) qtype: DnsType,
    pub(crate) qclass: DnsClass,
}

impl TryFrom<&[u8]> for DnsQuestion {
    type Error = ParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let qname = Name::try_from(value)?;

        let value = &value[qname.len()..];
        let qtype: u16 = ((value[0] as u16) << 8) | value[1] as u16;
        let qtype = DnsType::try_from(qtype)?;
        let qclass: u16 = ((value[2] as u16) << 8) | value[3] as u16;
        let qclass = DnsClass::try_from(qclass)?;

        Ok(DnsQuestion {
            qname,
            qtype,
            qclass,
        })
    }
}

impl DnsQuestion {
    pub(crate) fn len(&self) -> usize {
        self.qname.len() + 4
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

#[cfg(test)]
mod test {}
