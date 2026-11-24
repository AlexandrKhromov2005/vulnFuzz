use std::io::{self, Cursor, Read};

use vulnFuzz::agent::{
    Codec, Frame, HEADER_LEN, MAX_PAYLOAD_LEN, MessageKind, ProtocolError, ProtocolResult,
    ResponseCache,
};

fn request(payload: Vec<u8>) -> Frame {
    Frame::request(
        "episode-0000000000000001".parse().unwrap(),
        "step-0000000000000002".parse().unwrap(),
        7,
        0x0102_0304_0506_0708,
        payload,
    )
    .unwrap()
}

#[test]
fn round_trip_preserves_binary_payload_and_identity() {
    let codec = Codec::default();
    let request = request(vec![0, 0xff, b'a', 0, 0x80]);
    let encoded = codec.encode(&request).unwrap();
    assert_eq!(encoded.len(), HEADER_LEN + request.payload().len());
    assert_eq!(codec.decode(&encoded).unwrap(), request);

    let response = Frame::response_for(&request, vec![0xff, 0, 0xfe]);
    let decoded = codec.decode(&codec.encode(&response).unwrap()).unwrap();
    assert_eq!(decoded, response);
    assert_eq!(decoded.kind(), MessageKind::Response);
    assert_eq!(decoded.episode_id(), request.episode_id());
    assert_eq!(decoded.step_id(), request.step_id());
    assert_eq!(decoded.action_index(), 7);
    assert_eq!(decoded.request_id(), request.request_id());
    assert_eq!(decoded.payload(), &[0xff, 0, 0xfe]);
}

struct OneByteReader<R>(R);

impl<R: Read> Read for OneByteReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let length = buffer.len().min(1);
        self.0.read(&mut buffer[..length])
    }
}

#[test]
fn stream_codec_handles_fragmentation_and_consecutive_frames() {
    let codec = Codec::default();
    let first = request(vec![1, 0, 2]);
    let second = Frame::response_for(&first, vec![0xff, 0]);
    let mut stream = Vec::new();
    codec.write(&mut stream, &first).unwrap();
    codec.write(&mut stream, &second).unwrap();

    let mut reader = OneByteReader(Cursor::new(stream));
    assert_eq!(codec.read(&mut reader).unwrap(), first);
    assert_eq!(codec.read(&mut reader).unwrap(), second);
}

#[test]
fn rejects_unknown_and_reserved_envelope_fields() {
    let codec = Codec::default();
    let valid = codec.encode(&request(Vec::new())).unwrap();

    let mut frame = valid.clone();
    frame[0] ^= 1;
    assert!(matches!(codec.decode(&frame), Err(ProtocolError::BadMagic)));

    for (major, minor) in [(2, 0), (1, 1)] {
        let mut frame = valid.clone();
        frame[4] = major;
        frame[5] = minor;
        assert!(matches!(
            codec.decode(&frame),
            Err(ProtocolError::UnsupportedVersion { .. })
        ));
    }

    let mut frame = valid.clone();
    frame[6] = 3;
    assert!(matches!(
        codec.decode(&frame),
        Err(ProtocolError::UnknownMessageKind(3))
    ));

    let mut frame = valid.clone();
    frame[7] = 1;
    assert!(matches!(
        codec.decode(&frame),
        Err(ProtocolError::UnknownFlags(1))
    ));

    let mut frame = valid.clone();
    frame[8..10].copy_from_slice(&95u16.to_le_bytes());
    assert!(matches!(
        codec.decode(&frame),
        Err(ProtocolError::InvalidHeaderLength(95))
    ));

    for offset in [10, 11] {
        let mut frame = valid.clone();
        frame[offset] = 1;
        assert!(matches!(
            codec.decode(&frame),
            Err(ProtocolError::NonZeroReserved)
        ));
    }
}

#[test]
fn rejects_every_truncated_prefix() {
    let codec = Codec::default();
    let encoded = codec.encode(&request(vec![0, 1, 2, 3])).unwrap();
    for length in 0..encoded.len() {
        assert!(
            matches!(
                codec.decode(&encoded[..length]),
                Err(ProtocolError::Truncated)
            ),
            "prefix length {length} was accepted"
        );
    }

    let mut reader = Cursor::new(encoded[..encoded.len() - 1].to_vec());
    assert!(matches!(
        codec.read(&mut reader),
        Err(ProtocolError::Truncated)
    ));
}

#[test]
fn rejects_inconsistent_lengths_and_trailing_bytes() {
    let codec = Codec::default();
    let encoded = codec.encode(&request(vec![1, 2, 3, 4])).unwrap();

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(matches!(
        codec.decode(&trailing),
        Err(ProtocolError::TrailingBytes { .. })
    ));

    let mut shorter = encoded.clone();
    shorter[60..64].copy_from_slice(&3u32.to_le_bytes());
    assert!(matches!(
        codec.decode(&shorter),
        Err(ProtocolError::TrailingBytes { .. })
    ));

    let mut longer = encoded;
    longer[60..64].copy_from_slice(&5u32.to_le_bytes());
    assert!(matches!(
        codec.decode(&longer),
        Err(ProtocolError::Truncated)
    ));
}

#[test]
fn rejects_oversized_lengths_before_allocating_payload() {
    let codec = Codec::new(4).unwrap();
    let mut encoded = codec.encode(&request(vec![1, 2, 3, 4])).unwrap();
    encoded[60..64].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(matches!(
        codec.decode(&encoded),
        Err(ProtocolError::PayloadTooLarge {
            declared,
            limit: 4
        }) if declared == u32::MAX as u64
    ));

    let mut reader = Cursor::new(encoded);
    assert!(matches!(
        codec.read(&mut reader),
        Err(ProtocolError::PayloadTooLarge { limit: 4, .. })
    ));
}

#[test]
fn enforces_encoding_limits_and_allows_empty_payloads() {
    let codec = Codec::new(3).unwrap();
    assert!(codec.encode(&request(vec![0; 4])).is_err());
    assert!(matches!(
        Codec::new(MAX_PAYLOAD_LEN + 1),
        Err(ProtocolError::InvalidPayloadLimit(_))
    ));

    let empty_only = Codec::new(0).unwrap();
    let empty = request(Vec::new());
    assert_eq!(
        empty_only
            .decode(&empty_only.encode(&empty).unwrap())
            .unwrap(),
        empty
    );
    assert!(matches!(
        empty_only.encode(&request(vec![0])),
        Err(ProtocolError::PayloadTooLarge { limit: 0, .. })
    ));
    assert!(matches!(
        Frame::request(
            "episode-0000000000000001".parse().unwrap(),
            "step-0000000000000002".parse().unwrap(),
            0,
            0,
            Vec::new()
        ),
        Err(ProtocolError::InvalidRequestId)
    ));
}

#[test]
fn rejects_payload_corruption() {
    let codec = Codec::default();
    let mut encoded = codec.encode(&request(vec![0, 0xff, 3])).unwrap();
    *encoded.last_mut().unwrap() ^= 1;
    assert!(matches!(
        codec.decode(&encoded),
        Err(ProtocolError::PayloadHashMismatch)
    ));
}

#[test]
fn rejects_invalid_wire_identities() {
    let codec = Codec::default();
    let valid = codec.encode(&request(Vec::new())).unwrap();

    for offset in [28, 44] {
        let mut encoded = valid.clone();
        encoded[offset] = b'x';
        assert!(matches!(
            codec.decode(&encoded),
            Err(ProtocolError::InvalidIdentifier(_))
        ));
    }

    let mut encoded = valid;
    encoded[12..20].fill(0);
    assert!(matches!(
        codec.decode(&encoded),
        Err(ProtocolError::InvalidRequestId)
    ));
}

#[test]
fn duplicate_response_is_replayed_without_reexecution() {
    let request = request(vec![0, 0xff]);
    let expected = Frame::response_for(&request, vec![9, 0, 8]);
    let mut cache = ResponseCache::default();
    let mut executions = 0;

    let first = cache
        .respond_with(&request, || {
            executions += 1;
            Ok(expected.clone())
        })
        .unwrap()
        .clone();
    let second = cache
        .respond_with(&request, || {
            executions += 1;
            Ok(Frame::response_for(&request, b"must not run".to_vec()))
        })
        .unwrap()
        .clone();

    assert_eq!(executions, 1);
    assert_eq!(first, expected);
    assert_eq!(second, expected);
    assert_eq!(cache.len(), 1);

    let conflicting = Frame::request(
        request.episode_id().clone(),
        request.step_id().clone(),
        request.action_index(),
        request.request_id(),
        b"different".to_vec(),
    )
    .unwrap();
    let result = cache.respond_with(&conflicting, || -> ProtocolResult<Frame> {
        panic!("a conflicting duplicate must not execute")
    });
    assert!(matches!(result, Err(ProtocolError::ConflictingRequest)));
    assert_eq!(cache.len(), 1);
}

#[test]
fn response_cache_rejects_mismatched_response_identity() {
    let request = request(Vec::new());
    let other = Frame::request(
        "episode-0000000000000009".parse().unwrap(),
        request.step_id().clone(),
        request.action_index(),
        9,
        Vec::new(),
    )
    .unwrap();
    let mut cache = ResponseCache::default();
    let result = cache.respond_with(&request, || Ok(Frame::response_for(&other, Vec::new())));
    assert!(matches!(
        result,
        Err(ProtocolError::ResponseIdentityMismatch)
    ));
    assert!(cache.is_empty());
}
