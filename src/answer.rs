use crate::common::{DnsClass, DnsType, Name};

pub(crate) struct DnsAnswer {
    pub(crate) name: Name,
    pub(crate) qtype: DnsType,
    pub(crate) qclass: DnsClass,
    pub(crate) ttl: i32,
    rdlength: u16,
    rdata: RData,
}

pub(crate) enum RData {
    A([u8; 4]),
}

impl DnsAnswer {
    pub(crate) fn new(
        name: Name,
        qtype: DnsType,
        qclass: DnsClass,
        ttl: i32,
        rdata: RData,
    ) -> Self {
        let rdlength = match &rdata {
            RData::A(_) => 4,
        };

        DnsAnswer {
            name,
            qtype,
            qclass,
            ttl,
            rdlength,
            rdata,
        }
    }

    #[allow(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.name.len() + 10 + self.rdlength as usize
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.name.to_bytes());
        bytes.push((self.qtype as u16 >> 8) as u8);
        bytes.push(self.qtype as u8);
        bytes.push((self.qclass as u16 >> 8) as u8);
        bytes.push(self.qclass as u8);
        bytes.push((self.ttl >> 24) as u8);
        bytes.push((self.ttl >> 16) as u8);
        bytes.push((self.ttl >> 8) as u8);
        bytes.push(self.ttl as u8);
        bytes.push((self.rdlength >> 8) as u8);
        bytes.push(self.rdlength as u8);

        match &self.rdata {
            RData::A(ip) => {
                bytes.extend_from_slice(ip);
            }
        }

        bytes
    }
}
