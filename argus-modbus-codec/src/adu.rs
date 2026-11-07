use crate::error::{DecodeError, EncodeError};

use mbap::Mbap;
use pdu::Pdu;

#[derive(Debug, PartialEq, Eq)]
pub struct TcpAdu<'a> {
    pub mbap: Mbap,
    pub pdu: Pdu<'a>,
}

pub fn encode_into_slice(adu: &TcpAdu, dst: &mut [u8]) -> Result<usize, EncodeError> {
    let expected_length = 2 + adu.pdu.data.len();
    if adu.mbap.length as usize != expected_length || expected_length > 254 {
        return Err(EncodeError::InvalidLength);
    }

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

    // Builds a raw frame with the given MBAP length field followed by `pdu`.
    fn frame(transaction_id: u16, length: u16, unit_id: u8, pdu: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(7 + pdu.len());
        v.extend_from_slice(&transaction_id.to_be_bytes());
        v.extend_from_slice(&[0x00, 0x00]);
        v.extend_from_slice(&length.to_be_bytes());
        v.push(unit_id);
        v.extend_from_slice(pdu);
        v
    }

    // ---- ADU encode ----

    #[test]
    fn encode_exact_size_buffer() {
        let mut buf = [0u8; READ_SINGLE_COIL_REQUEST_BYTES.len()];
        let bytes = encode_into_slice(&READ_SINGLE_COIL_REQUEST_ADU, &mut buf).unwrap();
        assert_eq!(bytes, READ_SINGLE_COIL_REQUEST_BYTES.len());
        assert_eq!(buf, READ_SINGLE_COIL_REQUEST_BYTES);
    }

    #[test]
    fn encode_every_undersized_buffer_fails() {
        for size in 0..READ_SINGLE_COIL_REQUEST_BYTES.len() {
            let mut buf = vec![0u8; size];
            let err = encode_into_slice(&READ_SINGLE_COIL_REQUEST_ADU, &mut buf).unwrap_err();
            assert!(matches!(err, EncodeError::BufferTooSmall), "size {size}");
        }
    }

    #[test]
    fn encode_does_not_write_past_returned_length() {
        let mut buf = [0xEEu8; 260];
        let bytes = encode_into_slice(&READ_SINGLE_COIL_REQUEST_ADU, &mut buf).unwrap();
        assert!(buf[bytes..].iter().all(|&b| b == 0xEE));
    }

    #[test]
    fn encode_multibyte_fields_are_big_endian() {
        let adu = TcpAdu {
            mbap: Mbap {
                transaction_id: 0xABCD,
                protocol_id: 0x1234,
                length: 2,
                unit_id: 0xFF,
            },
            pdu: Pdu {
                function_code: 0x03,
                data: &[],
            },
        };
        let mut buf = [0u8; 8];
        let bytes = encode_into_slice(&adu, &mut buf).unwrap();
        assert_eq!(bytes, 8);
        assert_eq!(buf, [0xAB, 0xCD, 0x12, 0x34, 0x00, 0x02, 0xFF, 0x03]);
    }

    #[test]
    fn encode_empty_pdu_data() {
        let adu = TcpAdu {
            mbap: Mbap {
                transaction_id: 1,
                protocol_id: 0,
                length: 2,
                unit_id: 1,
            },
            pdu: Pdu {
                function_code: 0x07,
                data: &[],
            },
        };
        let mut buf = [0u8; 8];
        assert_eq!(encode_into_slice(&adu, &mut buf).unwrap(), 8);
        assert_eq!(buf, [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0x07]);
    }

    #[test]
    fn encode_max_size_adu() {
        let data = [0x5Au8; 252];
        let adu = TcpAdu {
            mbap: Mbap {
                transaction_id: 0xFFFF,
                protocol_id: 0,
                length: 254,
                unit_id: 0xFF,
            },
            pdu: Pdu {
                function_code: 0x10,
                data: &data,
            },
        };
        let mut buf = [0u8; 260];
        assert_eq!(encode_into_slice(&adu, &mut buf).unwrap(), 260);
        assert_eq!(buf[..8], [0xFF, 0xFF, 0x00, 0x00, 0x00, 0xFE, 0xFF, 0x10]);
        assert_eq!(buf[8..], data);
    }

    // ---- ADU encode: length field validation ----

    fn read_single_coil_with_length(length: u16) -> TcpAdu<'static> {
        TcpAdu {
            mbap: Mbap {
                length,
                ..READ_SINGLE_COIL_REQUEST_ADU.mbap
            },
            pdu: READ_SINGLE_COIL_REQUEST_ADU.pdu,
        }
    }

    #[test]
    fn encode_length_too_small_for_pdu() {
        let mut buf = [0u8; 260];
        let err = encode_into_slice(&read_single_coil_with_length(5), &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidLength));
    }

    #[test]
    fn encode_length_too_large_for_pdu() {
        let mut buf = [0u8; 260];
        let err = encode_into_slice(&read_single_coil_with_length(7), &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidLength));
    }

    #[test]
    fn encode_length_zero() {
        let mut buf = [0u8; 260];
        let err = encode_into_slice(&read_single_coil_with_length(0), &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidLength));
    }

    #[test]
    fn encode_every_mismatched_length_fails() {
        let mut buf = [0u8; 260];
        for length in (0..=u16::MAX).filter(|&l| l != 6) {
            let err =
                encode_into_slice(&read_single_coil_with_length(length), &mut buf).unwrap_err();
            assert!(matches!(err, EncodeError::InvalidLength), "length {length}");
        }
    }

    #[test]
    fn encode_invalid_length_leaves_buffer_untouched() {
        let mut buf = [0xEEu8; 260];
        let err = encode_into_slice(&read_single_coil_with_length(7), &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidLength));
        assert!(buf.iter().all(|&b| b == 0xEE));
    }

    #[test]
    fn encode_oversized_pdu_fails() {
        // 253 data bytes needs length 255, one past the Modbus maximum.
        let data = [0u8; 253];
        let adu = TcpAdu {
            mbap: Mbap {
                transaction_id: 1,
                protocol_id: 0,
                length: 255,
                unit_id: 0x11,
            },
            pdu: Pdu {
                function_code: 0x10,
                data: &data,
            },
        };
        let mut buf = [0u8; 300];
        let err = encode_into_slice(&adu, &mut buf).unwrap_err();
        assert!(matches!(err, EncodeError::InvalidLength));
    }

    #[test]
    fn encode_every_matching_length_writes_length_field() {
        let data = [0u8; 252];
        for data_len in 0..=252usize {
            let length = (data_len + 2) as u16;
            let adu = TcpAdu {
                mbap: Mbap {
                    transaction_id: 1,
                    protocol_id: 0,
                    length,
                    unit_id: 0x11,
                },
                pdu: Pdu {
                    function_code: 0x10,
                    data: &data[..data_len],
                },
            };
            let mut buf = [0u8; 260];
            let n = encode_into_slice(&adu, &mut buf).unwrap();
            assert_eq!(n, 6 + length as usize, "length {length}");
            assert_eq!(buf[4..6], length.to_be_bytes(), "length {length}");
        }
    }

    // ---- ADU decode: incomplete input ----

    #[test]
    fn decode_empty_input() {
        let err = decode_from_slice(&[]).unwrap_err();
        assert!(matches!(err, DecodeError::NeedMore));
    }

    #[test]
    fn decode_every_partial_mbap_needs_more() {
        for len in 0..7 {
            let err = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES[..len]).unwrap_err();
            assert!(matches!(err, DecodeError::NeedMore), "prefix {len}");
        }
    }

    #[test]
    fn decode_mbap_without_pdu() {
        let err = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES[..7]).unwrap_err();
        assert!(matches!(err, DecodeError::NeedMore));
    }

    #[test]
    fn decode_every_truncated_pdu_needs_more() {
        for len in 8..READ_SINGLE_COIL_REQUEST_BYTES.len() {
            let err = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES[..len]).unwrap_err();
            assert!(matches!(err, DecodeError::NeedMore), "prefix {len}");
        }
    }

    // ---- ADU decode: length field validation ----

    #[test]
    fn decode_length_zero() {
        let err = decode_from_slice(&frame(1, 0, 0x11, &[0x01])).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidLength));
    }

    #[test]
    fn decode_length_one() {
        let err = decode_from_slice(&frame(1, 1, 0x11, &[0x01])).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidLength));
    }

    #[test]
    fn decode_length_255() {
        let err = decode_from_slice(&frame(1, 255, 0x11, &[0x01; 254])).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidLength));
    }

    #[test]
    fn decode_every_out_of_range_length_is_invalid() {
        for length in (0..2).chain(255..=u16::MAX) {
            let err = decode_from_slice(&frame(1, length, 0x11, &[0x01])).unwrap_err();
            assert!(matches!(err, DecodeError::InvalidLength), "length {length}");
        }
    }

    #[test]
    fn decode_invalid_length_reported_before_missing_pdu() {
        let err = decode_from_slice(&frame(1, 0, 0x11, &[])).unwrap_err();
        assert!(matches!(err, DecodeError::InvalidLength));
    }

    #[test]
    fn decode_min_length_has_empty_data() {
        let src = frame(1, 2, 0x11, &[0x2B]);
        let (adu, bytes) = decode_from_slice(&src).unwrap();
        assert_eq!(bytes, 8);
        assert_eq!(adu.mbap.length, 2);
        assert_eq!(adu.pdu.function_code, 0x2B);
        assert!(adu.pdu.data.is_empty());
    }

    #[test]
    fn decode_max_length() {
        let mut pdu = [0xAAu8; 253];
        pdu[0] = 0x10;
        let src = frame(1, 254, 0x11, &pdu);
        let (adu, bytes) = decode_from_slice(&src).unwrap();
        assert_eq!(bytes, 260);
        assert_eq!(adu.pdu.function_code, 0x10);
        assert_eq!(adu.pdu.data, &pdu[1..]);
    }

    #[test]
    fn decode_every_valid_length() {
        for length in 2u16..=254 {
            let pdu: Vec<u8> = (0..length - 1).map(|i| i as u8).collect();
            let src = frame(7, length, 0x11, &pdu);
            let (adu, bytes) = decode_from_slice(&src).unwrap();
            assert_eq!(bytes, 6 + length as usize, "length {length}");
            assert_eq!(adu.mbap.length, length);
            assert_eq!(adu.pdu.function_code, pdu[0]);
            assert_eq!(adu.pdu.data, &pdu[1..]);
        }
    }

    // ---- ADU decode: field parsing ----

    #[test]
    fn decode_multibyte_fields_are_big_endian() {
        let src = [0xAB, 0xCD, 0x00, 0x00, 0x00, 0x02, 0xFF, 0x03];
        let (adu, _) = decode_from_slice(&src).unwrap();
        assert_eq!(adu.mbap.transaction_id, 0xABCD);
        assert_eq!(adu.mbap.length, 2);
        assert_eq!(adu.mbap.unit_id, 0xFF);
        assert_eq!(adu.pdu.function_code, 0x03);
    }

    #[test]
    fn decode_every_unit_id_and_function_code() {
        for byte in 0..=u8::MAX {
            let src = frame(1, 2, byte, &[byte]);
            let (adu, _) = decode_from_slice(&src).unwrap();
            assert_eq!(adu.mbap.unit_id, byte);
            assert_eq!(adu.pdu.function_code, byte);
        }
    }

    #[test]
    fn decode_exception_response() {
        // Read coils exception: illegal data address.
        let src = frame(2, 3, 0x11, &[0x81, 0x02]);
        let (adu, bytes) = decode_from_slice(&src).unwrap();
        assert_eq!(bytes, 9);
        assert_eq!(adu.pdu.function_code, 0x81);
        assert_eq!(adu.pdu.data, &[0x02]);
    }

    #[test]
    fn decode_read_holding_registers_response() {
        let src = frame(0x1234, 7, 0x01, &[0x03, 0x04, 0x00, 0x0A, 0x01, 0x02]);
        let (adu, bytes) = decode_from_slice(&src).unwrap();
        assert_eq!(bytes, 13);
        assert_eq!(adu.mbap.transaction_id, 0x1234);
        assert_eq!(adu.pdu.function_code, 0x03);
        assert_eq!(adu.pdu.data, &[0x04, 0x00, 0x0A, 0x01, 0x02]);
    }

    #[test]
    fn decode_data_borrows_from_input() {
        let (adu, _) = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES).unwrap();
        assert_eq!(
            adu.pdu.data.as_ptr(),
            READ_SINGLE_COIL_REQUEST_BYTES[8..].as_ptr()
        );
    }

    // ---- ADU decode: streams ----

    #[test]
    fn decode_leaves_trailing_bytes_unconsumed() {
        let mut src = READ_SINGLE_COIL_REQUEST_BYTES.to_vec();
        src.extend_from_slice(&[0xDE, 0xAD]);
        let (adu, bytes) = decode_from_slice(&src).unwrap();
        assert_eq!(bytes, READ_SINGLE_COIL_REQUEST_BYTES.len());
        assert_eq!(adu, READ_SINGLE_COIL_REQUEST_ADU);
    }

    #[test]
    fn decode_back_to_back_frames() {
        let mut src = READ_SINGLE_COIL_REQUEST_BYTES.to_vec();
        src.extend_from_slice(&frame(3, 2, 0x22, &[0x07]));

        let (first, used) = decode_from_slice(&src).unwrap();
        assert_eq!(used, 12);
        assert_eq!(first, READ_SINGLE_COIL_REQUEST_ADU);

        let (second, used2) = decode_from_slice(&src[used..]).unwrap();
        assert_eq!(used2, 8);
        assert_eq!(second.mbap.transaction_id, 3);
        assert_eq!(second.mbap.unit_id, 0x22);
        assert_eq!(second.pdu.function_code, 0x07);
        assert!(second.pdu.data.is_empty());
    }

    // ---- Round trips ----

    #[test]
    fn roundtrip_encode_then_decode() {
        let mut buf = [0u8; 260];
        let n = encode_into_slice(&READ_SINGLE_COIL_REQUEST_ADU, &mut buf).unwrap();
        let (adu, used) = decode_from_slice(&buf[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(adu, READ_SINGLE_COIL_REQUEST_ADU);
    }

    #[test]
    fn roundtrip_decode_then_encode() {
        let (adu, _) = decode_from_slice(&READ_SINGLE_COIL_REQUEST_BYTES).unwrap();
        let mut buf = [0u8; 260];
        let n = encode_into_slice(&adu, &mut buf).unwrap();
        assert_eq!(buf[..n], READ_SINGLE_COIL_REQUEST_BYTES);
    }

    #[test]
    fn roundtrip_every_valid_length() {
        let data = [0xC3u8; 252];
        for data_len in 0..=252usize {
            let adu = TcpAdu {
                mbap: Mbap {
                    transaction_id: data_len as u16,
                    protocol_id: 0,
                    length: (data_len + 2) as u16,
                    unit_id: 0x11,
                },
                pdu: Pdu {
                    function_code: 0x10,
                    data: &data[..data_len],
                },
            };
            let mut buf = [0u8; 260];
            let n = encode_into_slice(&adu, &mut buf).unwrap();
            assert_eq!(n, 8 + data_len);
            let (decoded, used) = decode_from_slice(&buf[..n]).unwrap();
            assert_eq!(used, n);
            assert_eq!(decoded, adu);
        }
    }

    // ---- MBAP ----

    #[test]
    fn mbap_encode_writes_exactly_seven_bytes() {
        let mbap = Mbap {
            transaction_id: 0x0102,
            protocol_id: 0x0304,
            length: 0x0506,
            unit_id: 0x07,
        };
        let mut buf = [0xEEu8; 10];
        assert_eq!(mbap::encode_into_slice(&mbap, &mut buf).unwrap(), 7);
        assert_eq!(
            buf,
            [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xEE, 0xEE, 0xEE]
        );
    }

    #[test]
    fn mbap_encode_buffer_too_small() {
        let mbap = READ_SINGLE_COIL_REQUEST_ADU.mbap;
        for size in 0..7 {
            let mut buf = vec![0u8; size];
            let err = mbap::encode_into_slice(&mbap, &mut buf).unwrap_err();
            assert!(matches!(err, EncodeError::BufferTooSmall), "size {size}");
        }
    }

    #[test]
    fn mbap_decode_reads_exactly_seven_bytes() {
        let src = [0x00, 0x02, 0x00, 0x00, 0x00, 0x06, 0x11, 0xFF, 0xFF];
        let (mbap, bytes) = mbap::decode_from_slice(&src).unwrap();
        assert_eq!(bytes, 7);
        assert_eq!(mbap, READ_SINGLE_COIL_REQUEST_ADU.mbap);
    }

    #[test]
    fn mbap_decode_preserves_protocol_id() {
        let src = [0x00, 0x01, 0xBE, 0xEF, 0x00, 0x02, 0x01];
        let (mbap, _) = mbap::decode_from_slice(&src).unwrap();
        assert_eq!(mbap.protocol_id, 0xBEEF);
    }

    #[test]
    fn mbap_decode_length_bounds() {
        for (length, ok) in [
            (0u16, false),
            (1, false),
            (2, true),
            (254, true),
            (255, false),
            (u16::MAX, false),
        ] {
            let mut src = [0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01];
            src[4..6].copy_from_slice(&length.to_be_bytes());
            let result = mbap::decode_from_slice(&src);
            if ok {
                assert_eq!(result.unwrap().0.length, length);
            } else {
                assert!(
                    matches!(result.unwrap_err(), DecodeError::InvalidLength),
                    "length {length}"
                );
            }
        }
    }

    // ---- PDU ----

    #[test]
    fn pdu_encode_writes_function_code_then_data() {
        let pdu = Pdu {
            function_code: 0x06,
            data: &[0x00, 0x01, 0x00, 0x03],
        };
        let mut buf = [0xEEu8; 8];
        assert_eq!(pdu::encode_into_slice(&pdu, &mut buf).unwrap(), 5);
        assert_eq!(buf, [0x06, 0x00, 0x01, 0x00, 0x03, 0xEE, 0xEE, 0xEE]);
    }

    #[test]
    fn pdu_encode_buffer_too_small() {
        let pdu = Pdu {
            function_code: 0x06,
            data: &[0x00, 0x01, 0x00, 0x03],
        };
        for size in 0..5 {
            let mut buf = vec![0u8; size];
            let err = pdu::encode_into_slice(&pdu, &mut buf).unwrap_err();
            assert!(matches!(err, EncodeError::BufferTooSmall), "size {size}");
        }
    }

    #[test]
    fn pdu_decode_empty_input() {
        let err = pdu::decode_from_slice(&[], 0).unwrap_err();
        assert!(matches!(err, DecodeError::NeedMore));
    }

    #[test]
    fn pdu_decode_function_code_only() {
        let (pdu, bytes) = pdu::decode_from_slice(&[0x07], 0).unwrap();
        assert_eq!(bytes, 1);
        assert_eq!(pdu.function_code, 0x07);
        assert!(pdu.data.is_empty());
    }

    #[test]
    fn pdu_decode_uses_data_len_not_slice_len() {
        let src = [0x03, 0x01, 0x02, 0x03, 0x04];
        let (pdu, bytes) = pdu::decode_from_slice(&src, 1).unwrap();
        assert_eq!(bytes, 2);
        assert_eq!(pdu.function_code, 0x03);
        assert_eq!(pdu.data, &[0x01]);
    }

    #[test]
    fn pdu_decode_every_truncation_needs_more() {
        let src = [0x03, 0x01, 0x02, 0x03, 0x04];
        for len in 0..src.len() {
            let err = pdu::decode_from_slice(&src[..len], 4).unwrap_err();
            assert!(matches!(err, DecodeError::NeedMore), "prefix {len}");
        }
    }
}
