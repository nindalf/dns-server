use crate::{answer::DnsAnswer, error::ParseError, header::DnsHeader, question::DnsQuestion};

pub(crate) struct DnsPacket {
    pub(crate) header: DnsHeader,
    pub(crate) questions: Vec<DnsQuestion>,
    pub(crate) answers: Vec<DnsAnswer>,
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

        let answers = Vec::new();

        Ok(DnsPacket {
            header,
            questions,
            answers,
        })
    }

    pub(crate) fn add_answer(&mut self, answer: DnsAnswer) {
        self.header.ancount += 1;
        self.answers.push(answer);
    }

    pub(crate) fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = self.header.to_bytes();
        for question in &self.questions {
            bytes.extend_from_slice(&question.to_bytes());
        }
        for answer in &self.answers {
            bytes.extend_from_slice(&answer.to_bytes());
        }
        bytes
    }
}
