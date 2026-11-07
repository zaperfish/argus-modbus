#[derive(Debug)]
pub enum EncodeError {
    BufferTooSmall,
    InvalidLength,
}

#[derive(Debug)]
pub enum DecodeError {
    NeedMore,
    InvalidLength,
}
