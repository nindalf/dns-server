use crate::{error::ParseError, header::DnsHeader, question::DnsQuestion};

pub(crate) struct DnsPacket {
    pub(crate) header: DnsHeader,
    pub(crate) questions: Vec<DnsQuestion>,
}

impl DnsPacket {
    pub(crate) fn try_from(bytes: &[u8]) -> Result<Self, ParseError> {
        let header = DnsHeader::try_from(bytes)?;
        let mut offset = 12;
        let mut bytes = bytes;
        let mut questions = Vec::new();

        for _ in 0..header.qdcount {
            bytes = &bytes[offset..];
            if bytes.is_empty() {
                break;
            }
            let question = DnsQuestion::try_from(bytes)?;
            offset += question.len();
            questions.push(question);
        }

        Ok(DnsPacket { header, questions })
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }
        bytes
    }
}
