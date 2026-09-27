use super::*;

#[test]
fn pae_matches_the_dsse_spec_example() {
    assert_eq!(
        pae("http://example.com/HelloWorld", b"hello world"),
        b"DSSEv1 29 http://example.com/HelloWorld 11 hello world".to_vec()
    );
}

#[test]
fn envelope_uses_dsse_field_names() {
    let env = DsseEnvelope {
        payload_type: "t".to_string(),
        payload: "cA==".to_string(),
        signatures: vec![DsseSignature {
            keyid: "k".to_string(),
            sig: "s".to_string(),
        }],
    };
    assert_eq!(
        serde_json::to_value(&env).unwrap(),
        serde_json::json!({"payloadType": "t", "payload": "cA==",
            "signatures": [{"keyid": "k", "sig": "s"}]})
    );
}

#[cfg(feature = "signing")]
mod signing {
    use super::*;
    use crate::execution::tests::sample;
    use crate::execution::{EXECUTION_AUTHORISATION_PAYLOAD_TYPE, ValidationError};
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;
    use ed25519_dalek::{Signer, SigningKey};

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    /// Re-sign an arbitrary payload, to test what `verify` does with bytes
    /// `sign` would never produce.
    fn sign_raw(payload: &[u8], k: &SigningKey) -> DsseEnvelope {
        let sig = k.sign(&pae(EXECUTION_AUTHORISATION_PAYLOAD_TYPE, payload));
        DsseEnvelope {
            payload_type: EXECUTION_AUTHORISATION_PAYLOAD_TYPE.to_string(),
            payload: STANDARD.encode(payload),
            signatures: vec![DsseSignature {
                keyid: key_id(&k.verifying_key()),
                sig: STANDARD.encode(sig.to_bytes()),
            }],
        }
    }

    #[test]
    fn a_signed_authorisation_round_trips() {
        let k = key(1);
        let env = sign(&sample(), &k).unwrap();
        assert_eq!(env.signatures[0].keyid, key_id(&k.verifying_key()));
        assert_eq!(verify(&env, &[k.verifying_key()]).unwrap(), sample());
    }

    #[test]
    fn signing_is_deterministic() {
        let k = key(1);
        assert_eq!(sign(&sample(), &k).unwrap(), sign(&sample(), &k).unwrap());
    }

    #[test]
    fn one_flipped_payload_byte_is_untrusted() {
        let k = key(1);
        let mut env = sign(&sample(), &k).unwrap();
        let mut bytes = STANDARD.decode(&env.payload).unwrap();
        // Flip a byte inside a digest so the JSON stays well-formed.
        let pos = bytes.len() / 2;
        bytes[pos] ^= 0x01;
        env.payload = STANDARD.encode(&bytes);
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn a_wrong_key_is_untrusted() {
        let env = sign(&sample(), &key(1)).unwrap();
        assert!(matches!(
            verify(&env, &[key(2).verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn no_trusted_keys_trusts_nothing() {
        let env = sign(&sample(), &key(1)).unwrap();
        assert!(matches!(
            verify(&env, &[]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn the_envelope_keyid_is_not_trusted_on_its_own() {
        let mut env = sign(&sample(), &key(2)).unwrap();
        env.signatures[0].keyid = key_id(&key(1).verifying_key());
        assert!(matches!(
            verify(&env, &[key(1).verifying_key()]),
            Err(VerifyError::NoTrustedSignature)
        ));
    }

    #[test]
    fn a_trusted_signature_beside_a_malformed_one_counts() {
        let k = key(1);
        let mut env = sign(&sample(), &k).unwrap();
        env.signatures.insert(
            0,
            DsseSignature {
                keyid: String::new(),
                sig: "not base64!".to_string(),
            },
        );
        assert!(verify(&env, &[key(3).verifying_key(), k.verifying_key()]).is_ok());
    }

    #[test]
    fn a_wrong_payload_type_is_refused() {
        let k = key(1);
        let mut env = sign(&sample(), &k).unwrap();
        env.payload_type = "application/json".to_string();
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::WrongPayloadType)
        ));
    }

    #[test]
    fn a_non_base64_payload_is_refused() {
        let k = key(1);
        let mut env = sign(&sample(), &k).unwrap();
        env.payload = "%%%".to_string();
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::BadEncoding)
        ));
    }

    #[test]
    fn an_unknown_operation_is_a_bad_payload() {
        let k = key(1);
        let mut v = serde_json::to_value(sample()).unwrap();
        v["operation"] = serde_json::json!("delete_everything");
        let env = sign_raw(&serde_json::to_vec(&v).unwrap(), &k);
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::BadPayload(_))
        ));
    }

    #[test]
    fn an_unknown_schema_is_invalid() {
        let k = key(1);
        let mut a = sample();
        a.schema = "greentic.execution-authorisation.v9".to_string();
        let env = sign(&a, &k).unwrap();
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::Invalid(ValidationError::UnknownSchema(_)))
        ));
    }

    #[test]
    fn bad_traffic_steps_are_invalid_after_verification() {
        let k = key(1);
        let mut a = sample();
        a.traffic.steps = vec![50, 10];
        let env = sign(&a, &k).unwrap();
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::Invalid(ValidationError::BadTrafficSteps))
        ));
    }

    #[test]
    fn duplicate_units_are_invalid_after_verification() {
        let k = key(1);
        let mut a = sample();
        a.units.push(a.units[0].clone());
        let env = sign(&a, &k).unwrap();
        assert!(matches!(
            verify(&env, &[k.verifying_key()]),
            Err(VerifyError::Invalid(ValidationError::DuplicateUnit(_)))
        ));
    }

    #[test]
    fn key_id_is_16_hex_of_sha256() {
        let vk = key(1).verifying_key();
        let id = key_id(&vk);
        assert_eq!(id.len(), 16);
        let full =
            crate::release::hex_lower(&<sha2::Sha256 as sha2::Digest>::digest(vk.as_bytes()));
        assert_eq!(id, full[..16]);
    }

    #[test]
    fn trusted_keys_parse_and_round_trip() {
        let (a, b) = (key(1).verifying_key(), key(2).verifying_key());
        let list = format!(
            " {} ,, {} ,",
            format_trusted_key(&a),
            format_trusted_key(&b)
        );
        assert_eq!(parse_trusted_keys(&list).unwrap(), vec![a, b]);
        assert_eq!(parse_trusted_keys("").unwrap(), vec![]);
        assert_eq!(parse_trusted_keys("  ").unwrap(), vec![]);
    }

    #[test]
    fn malformed_trusted_keys_refuse_the_whole_list() {
        let good = format_trusted_key(&key(1).verifying_key());
        assert_eq!(
            parse_trusted_keys(&format!("{good},rsa:abc")),
            Err(TrustedKeyError::UnsupportedAlgorithm(1))
        );
        assert_eq!(
            parse_trusted_keys("ed25519:***"),
            Err(TrustedKeyError::BadBase64(0))
        );
        assert_eq!(
            parse_trusted_keys(&format!("ed25519:{}", STANDARD.encode([7u8; 31]))),
            Err(TrustedKeyError::BadLength(0))
        );
    }
}
