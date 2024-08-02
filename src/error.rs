use thiserror::Error;

#[derive(PartialEq, Debug, Error)]
pub(crate) enum ParseError {
    #[error("unparseable value: {0}")]
    InvalidValue(u8),
}
