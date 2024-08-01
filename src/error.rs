use thiserror::Error;

#[derive(PartialEq, Debug, Error)]
pub(crate) enum ParseError {
    #[error("expected 12 bytes, found {0}")]
    InvalidLength(usize),
    #[error("unparseable value: {0}")]
    InvalidValue(u8),
}
