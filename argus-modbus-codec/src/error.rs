#[derive(Debug)]
pub enum EncodeError {
    BufferTooSmall,
}

#[derive(Debug)]
pub enum DecodeError {
    NeedMore,
    InvalidLength,
}
