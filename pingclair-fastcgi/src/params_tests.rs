// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Dorian Verlaine

//! 🧾 Parameters retain complete pairs within PHP-FPM-compatible records.

use super::*;

/// 🧾 Decode the stream independently of the client's encoder.
fn decode_params(mut bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    fn size(bytes: &mut &[u8]) -> usize {
        let first = bytes[0];
        if first & 0x80 == 0 {
            *bytes = &bytes[1..];
            first as usize
        } else {
            let length = u32::from_be_bytes(bytes[..4].try_into().unwrap()) & 0x7fff_ffff;
            *bytes = &bytes[4..];
            length as usize
        }
    }
    let mut params = BTreeMap::new();
    while !bytes.is_empty() {
        let name_length = size(&mut bytes);
        let value_length = size(&mut bytes);
        let name = String::from_utf8(bytes[..name_length].to_vec()).unwrap();
        bytes = &bytes[name_length..];
        let value = bytes[..value_length].to_vec();
        bytes = &bytes[value_length..];
        params.insert(name, value);
    }
    params
}

/// 🛡️ Reject an oversized value or name before writing even an earlier valid pair.
#[tokio::test]
async fn oversized_params_are_refused_before_any_params_record() {
    for (name, value) in [
        ("HTTP_X_NEAR_LIMIT".to_string(), vec![b'x'; 65_500]),
        (
            "HTTP_X_LARGE".to_string(),
            vec![0xff; MAX_RECORD_CONTENT * 3],
        ),
        (
            "N".repeat(MAX_RECORD_CONTENT + 1),
            b"name-too-large".to_vec(),
        ),
    ] {
        let params = BTreeMap::from([
            ("A".to_string(), b"earlier-parameter".to_vec()),
            (name, value),
        ]);
        let (client_half, mut server_half) = tokio::io::duplex(MAX_RECORD_CONTENT * 4);
        let mut client = Client::new(client_half, 1, None, None, false);
        assert!(matches!(
            client.send_params(&params).await,
            Err(FastCgiError::ParamsTooLarge)
        ));
        drop(client);
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        server_half.read_to_end(&mut bytes).await.unwrap();
        assert!(
            bytes.is_empty(),
            "a rejected environment must send no PARAMS"
        );
    }
}

/// 🐘 A maximum-size accepted pair stays whole and preserves following parameters.
#[tokio::test]
async fn boundary_params_round_trip_as_complete_pairs() {
    let params = BTreeMap::from([
        ("A".to_string(), vec![0xff; MAX_RECORD_CONTENT - 6]),
        ("B".repeat(128), vec![b'b'; 127]),
        ("Z_AFTER".to_string(), b"following-parameter".to_vec()),
    ]);
    let (client_half, mut server_half) = tokio::io::duplex(1024);
    let reader = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut received = BTreeMap::new();
        let mut sizes = Vec::new();
        loop {
            let mut header = [0; 8];
            server_half.read_exact(&mut header).await.unwrap();
            assert_eq!(&header[..4], &[1, 4, 0, 1]);
            let length = u16::from_be_bytes([header[4], header[5]]) as usize;
            assert!(length <= MAX_RECORD_CONTENT);
            let mut content = vec![0; length + header[6] as usize];
            server_half.read_exact(&mut content).await.unwrap();
            if length == 0 {
                break;
            }
            // 🐘 Decoding each record separately models PHP-FPM's boundary rule.
            received.extend(decode_params(&content[..length]));
            sizes.push(length);
        }
        (received, sizes)
    });
    let mut client = Client::new(client_half, 1, None, None, false);
    client.send_params(&params).await.unwrap();
    let (received, sizes) = reader.await.unwrap();
    assert_eq!(received, params);
    assert_eq!(sizes, vec![MAX_RECORD_CONTENT, 288]);
}
