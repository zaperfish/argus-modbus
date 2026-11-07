use crate::error::{DecodeError, EncodeError};

use mbap::Mbap;
use pdu::Pdu;

#[derive(Debug, PartialEq, Eq)]
pub struct TcpAdu<'a> {
    pub mbap: Mbap,
    pub pdu: Pdu<'a>,
}

pub fn encode_into_slice(adu: &TcpAdu, dst: &mut [u8]) -> Result<usize, EncodeError> {
    let mbap_bytes = mbap::encode_into_slice(&adu.mbap, dst)?;
    let pdu_bytes = pdu::encode_into_slice(&adu.pdu, &mut dst[mbap_bytes..])?;

    Ok(mbap_bytes + pdu_bytes)
}

pub fn decode_from_slice(src: &[u8]) -> Result<(TcpAdu<'_>, usize), DecodeError> {
    let (mbap, mbap_bytes) = mbap::decode_from_slice(src)?;
    let (pdu, pdu_bytes) = pdu::decode_from_slice(&src[mbap_bytes..], mbap.length as usize - 2)?;

    Ok((TcpAdu { mbap, pdu }, mbap_bytes + pdu_bytes))
}

mod mbap {
    use super::*;

    const MBAP_LEN: usize = 7;
    const MIN_LENGTH: usize = 2;
    const MAX_LENGTH: usize = 254;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Mbap {
        pub transaction_id: u16,
        pub protocol_id: u16,
        pub length: u16,
        pub unit_id: u8,
    }

    pub fn encode_into_slice(mbap: &Mbap, dst: &mut [u8]) -> Result<usize, EncodeError> {
        if dst.len() < MBAP_LEN {
            return Err(EncodeError::BufferTooSmall);
        }

        dst[0..2].copy_from_slice(&mbap.transaction_id.to_be_bytes());
        dst[2..4].copy_from_slice(&mbap.protocol_id.to_be_bytes());
        dst[4..6].copy_from_slice(&mbap.length.to_be_bytes());
        dst[6] = mbap.unit_id;

        Ok(MBAP_LEN)
    }

    pub fn decode_from_slice(src: &[u8]) -> Result<(Mbap, usize), DecodeError> {
        if src.len() < MBAP_LEN {
            return Err(DecodeError::NeedMore);
        }

        let mbap = Mbap {
            transaction_id: u16::from_be_bytes([src[0], src[1]]),
            protocol_id: u16::from_be_bytes([src[2], src[3]]),
            length: u16::from_be_bytes([src[4], src[5]]),
            unit_id: src[6],
        };

        if !(MIN_LENGTH..=MAX_LENGTH).contains(&(mbap.length as usize)) {
            return Err(DecodeError::InvalidLength);
        }

        Ok((mbap, MBAP_LEN))
    }
}

mod pdu {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    pub struct Pdu<'a> {
        pub function_code: u8,
        pub data: &'a [u8],
    }

    pub fn encode_into_slice(pdu: &Pdu, dst: &mut [u8]) -> Result<usize, EncodeError> {
        let len = 1 + pdu.data.len();
        if dst.len() < len {
            return Err(EncodeError::BufferTooSmall);
        }

        dst[0] = pdu.function_code;
        dst[1..len].copy_from_slice(pdu.data);

        Ok(len)
    }

    pub fn decode_from_slice(src: &[u8], data_len: usize) -> Result<(Pdu<'_>, usize), DecodeError> {
        if src.len() < 1 + data_len {
            return Err(DecodeError::NeedMore);
        }

        let pdu = Pdu {
            function_code: src[0],
            data: &src[1..=data_len],
        };

        let bytes_read = 1 + pdu.data.len();

        Ok((pdu, bytes_read))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const READ_SINGLE_COIL_REQUEST_BYTES: [u8; 12] = [
        0x00, 0x02, // transaction id
        0x00, 0x00, // protocol id
        0x00, 0x06, // length: unit id + PDU
        0x11, // unit id
        0x01, // function code: read coils
        0x00, 0x13, // start address: coil 20 (0-based 0x0013)
        0x00, 0x01, // quantity: 1 coil
    ];

    const READ_SINGLE_COIL_REQUEST_ADU: TcpAdu = TcpAdu {
        mbap: Mbap {
            transaction_id: 2,
            protocol_id: 0,
            length: 6,
            unit_id: 0x11,
        },
        pdu: Pdu {
            function_code: 0x01,
            data: &[0x00, 0x13, 0x00, 0x01],
        },
    };

    #[test]
    fn encode_valid_adu() {
        let mut buf: [u8; 260] = [0; 260];
        let bytes = encode_into_slice(&READ_SINGLE_COIL_REQUEST_ADU, &mut buf).unwrap();
        assert_eq!(bytes, READ_SINGLE_COIL_REQUEST_BYTES.len());
        assert_eq!(buf[..bytes], READ_SINGLE_COIL_REQUEST_BYTES);
    }

    #[test]
    fn decode_valid_adu() {
        let (adu, bytes) = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES).unwrap();
        assert_eq!(bytes, READ_SINGLE_COIL_REQUEST_BYTES.len());
        assert_eq!(adu, READ_SINGLE_COIL_REQUEST_ADU);
    }
}
