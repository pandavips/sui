// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use hex_literal::hex;
use std::collections::HashMap;
use std::time::SystemTime;

use crate::error::{SuiError, SuiResult};

use boring_signal::bn::BigNum;
use boring_signal::ecdsa::EcdsaSig;
use boring_signal::stack;
use boring_signal::x509::store::X509StoreBuilder;
use boring_signal::x509::{X509StoreContext, X509};
use ciborium::value::{Integer, Value};
use prost::DecodeError;
use sha2::{Digest, Sha384};
use strum::Display;
use subtle::ConstantTimeEq;

/// A replacement for [`std::collections::HashMap`] that performs linear lookups.
///
/// This can be used in place of `HashMap` for supporting lookup in `const`
/// arrays. For small `N`, the linear search will be faster than a hash lookup.
struct SmallMap<K, V, const N: usize>([(K, V); N]);

impl<K, V, const N: usize> SmallMap<K, V, N> {
    /// The maximum number of elements allowed in a `SmallMap`.
    const MAX_SIZE: usize = 10;

    /// Checks at compile-time (via `const`) that `N` is small enough.
    const CHECK_MAX_SIZE: () = assert!(
        N <= Self::MAX_SIZE,
        "use a HashMap for more than MAX_SIZE items"
    );

    /// Creates a new `SmallMap` with the given contents.
    pub(crate) const fn new(items: [(K, V); N]) -> Self {
        // Evaluate CHECK_MAX_SIZE; this will fail compilation if `N` is too
        // large.
        //
        // TODO(https://github.com/rust-lang/rust-clippy/issues/9048): Remove
        // the unnecessary #[allow].
        #[allow(clippy::let_unit_value)]
        let _: () = Self::CHECK_MAX_SIZE;
        Self(items)
    }

    /// Gets the value for the first key that matches `key`, or `None`.
    pub(crate) fn get<Q: PartialEq<K> + ?Sized>(&self, key: &Q) -> Option<&V> {
        self.0.iter().find_map(|(k, v)| (key == k).then_some(v))
    }
}

const ROOT_CERTIFICATE_PEM: &[u8] = include_bytes!("./nitro_root_certificate.pem");

#[derive(Debug, Display, thiserror::Error, PartialEq, Eq)]
pub enum NitroError {
    /// Invalid CBOR
    InvalidCbor,
    /// Invalid COSE_Sign1
    InvalidCoseSign1,
    /// Invalid signature
    InvalidSignature,
    /// Invalid attestation document
    InvalidAttestationDoc,
    /// Invalid certificate: {0}
    InvalidCertificate(String),
    /// Invalid PCRs
    InvalidPcrs,
    /// Invalid Public Key
    InvalidPublicKey,
    /// User data field is absent from the attestation document
    UserDataMissing,
    /// Invalid User Data
    InvalidUserData,
}

impl From<ciborium::de::Error<std::io::Error>> for NitroError {
    fn from(_err: ciborium::de::Error<std::io::Error>) -> NitroError {
        NitroError::InvalidCbor
    }
}

impl From<boring_signal::error::ErrorStack> for NitroError {
    fn from(err: boring_signal::error::ErrorStack) -> NitroError {
        NitroError::InvalidCertificate(err.to_string())
    }
}

impl From<DecodeError> for NitroError {
    fn from(_err: DecodeError) -> Self {
        NitroError::InvalidUserData
    }
}

// A type for Platform Configuration Register values
// They are Sha-384 hashes, 48 byte long.
// https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where
pub(crate) type Pcr = [u8; 48];

// We only ever validate PCRs 0, 1, and 2.
pub(crate) type PcrMap = SmallMap<usize, Pcr, 3>;
pub const ENCLAVE_ID_SVR3_NITRO_STAGING: &[u8] = b"5d16a1fd.52b91975.6c355155";

const NITRO_EXPECTED_PCRS: PcrMap = SmallMap::new([
    (0, hex!("5d16a1fdbf39bfcd6265b147e985964fcfe31bb1f319a493c7af8f74234752b21161ea0a8b928ab67bd4765657ef68c6")),
    (1, hex!("52b919754e1643f4027eeee8ec39cc4a2cb931723de0c93ce5cc8d407467dc4302e86490c01c0d755acfe10dbf657546")),
    (2, hex!("6c35515508b8d289dd0ffae75c0e6ee57662bdd46d316a623573d9913cf76a4c603924d3f3484478f94757628756763e")),
]);

/// https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
pub fn attestation_verify_inner(attestation: &[u8], pk: &[u8]) -> SuiResult<()> {
    let cose_sign1 = CoseSign1::from_bytes(attestation).unwrap();
    let now = SystemTime::now();
    let doc = cose_sign1.extract_attestation_doc(now).unwrap();
    doc.validate_pcrs(&NITRO_EXPECTED_PCRS).unwrap();
    let user_data = doc.user_data.ok_or(SuiError::TypeError {
        error: "user data missing".to_string(),
    })?;
    if user_data.ct_eq(pk).into() {
        Ok(())
    } else {
        Err(SuiError::TypeError {
            error: "user data mismatch".to_string(),
        })
    }
}

struct CoseSign1 {
    protected_header: Vec<u8>,
    // nitro has no unprotected header
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl CoseSign1 {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, NitroError> {
        let value: Value = ciborium::de::from_reader(bytes)?;
        value.try_into()
    }

    pub fn extract_attestation_doc(&self, now: SystemTime) -> Result<AttestationDoc, NitroError> {
        let hash = Sha384::digest(self.to_canonical());
        let r = BigNum::from_slice(&self.signature[..48]).expect("can extract r");
        let s = BigNum::from_slice(&self.signature[48..]).expect("can extract s");
        let sig = EcdsaSig::from_private_components(r, s).expect("can initialize signature");

        let doc = AttestationDoc::from_bytes(self.payload.as_slice()).expect("can parse doc");
        let cert = doc.verified_cert(now)?;
        let key = cert
            .public_key()
            .and_then(|pub_key| pub_key.ec_key())
            .expect("has EC key");
        let is_valid = sig.verify(hash.as_slice(), &key).expect("can verify");
        if !is_valid {
            return Err(NitroError::InvalidSignature);
        }
        Ok(doc)
    }

    fn validating_new(
        protected_header: Vec<u8>,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<Self, NitroError> {
        let is_valid = {
            let mut is_valid = true;
            is_valid &= Self::is_valid_protected_header(&protected_header);
            is_valid &= (1..16384).contains(&payload.len());
            is_valid &= signature.len() == 96;
            is_valid
        };
        if !is_valid {
            return Err(NitroError::InvalidCoseSign1);
        }
        Ok(CoseSign1 {
            protected_header,
            payload,
            signature,
        })
    }

    fn is_valid_protected_header(bytes: &[u8]) -> bool {
        let signing_algorithm: Integer = Integer::from(1);
        let ecdsa_sha_384: Integer = Integer::from(-35);
        let value: Value = ciborium::de::from_reader(bytes).expect("valid cbor");
        match value {
            Value::Map(vec) => match &vec[..] {
                [(Value::Integer(key), Value::Integer(val))] => {
                    key == &signing_algorithm && val == &ecdsa_sha_384
                }
                _ => false,
            },
            _ => false,
        }
    }

    fn to_canonical(&self) -> Vec<u8> {
        let value = Value::Array(vec![
            Value::Text("Signature1".to_string()),
            Value::Bytes(self.protected_header.clone()),
            Value::Bytes(vec![]),
            Value::Bytes(self.payload.clone()),
        ]);
        let mut bytes = Vec::with_capacity(self.protected_header.len() + self.payload.len());
        ciborium::ser::into_writer(&value, &mut bytes).expect("can write bytes");
        bytes
    }
}

impl TryFrom<Value> for CoseSign1 {
    type Error = NitroError;

    // Assumes tagged CBOR encoding of COSE_Sign1
    fn try_from(value: Value) -> Result<CoseSign1, NitroError> {
        let parts: [Value; 4] = value
            .as_array()
            .ok_or(NitroError::InvalidCoseSign1)?
            .to_vec()
            .try_into()
            .map_err(|_| NitroError::InvalidCoseSign1)?;
        match parts {
            [Value::Bytes(protected_header), Value::Map(_), Value::Bytes(payload), Value::Bytes(signature)] => {
                CoseSign1::validating_new(protected_header, payload, signature)
            }
            _ => Err(NitroError::InvalidCoseSign1),
        }
    }
}

// Values of the fields are validated as they are read from the CBOR value and are not used beyond
// that. Marking them as allowed dead code for now until it is clear we don't really even need them
// after extracting the public key.
#[allow(dead_code)]
struct AttestationDoc {
    module_id: String,
    digest: String,
    timestamp: i64,
    pcrs: Vec<(usize, Vec<u8>)>,
    certificate: Vec<u8>,
    cabundle: Vec<Vec<u8>>,
    public_key: Option<Vec<u8>>,
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
}

impl TryFrom<Value> for AttestationDoc {
    type Error = NitroError;

    fn try_from(value: Value) -> Result<AttestationDoc, NitroError> {
        let map = AttestationDoc::parse_as_cbor_map(value)?;
        Self::from_cbor_map(map)
    }
}

type CborMap = HashMap<String, Value>;

impl AttestationDoc {
    fn from_bytes(bytes: &[u8]) -> Result<AttestationDoc, NitroError> {
        let value: Value = ciborium::de::from_reader(bytes)?;
        value.try_into()
    }

    fn parse_as_cbor_map(value: Value) -> Result<CborMap, NitroError> {
        value
            .as_map()
            .unwrap()
            .into_iter()
            .map(|(k, v)| {
                let k = k.as_text().ok_or(NitroError::InvalidAttestationDoc)?;
                Ok((k.to_string(), v.clone()))
            })
            .collect()
    }

    fn from_cbor_map(mut map: CborMap) -> Result<AttestationDoc, NitroError> {
        let module_id = map
            .remove("module_id")
            .and_then(|value| value.as_text().map(String::from))
            .filter(|s| !s.is_empty())
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let digest = map
            .remove("digest")
            .and_then(|value| value.as_text().map(String::from))
            .filter(|s| *s == "SHA384")
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let timestamp = map
            .remove("timestamp")
            .and_then(|value| value.as_integer())
            .and_then(|integer| i64::try_from(integer).ok())
            .filter(|i| i.is_positive())
            .ok_or(NitroError::InvalidAttestationDoc)?;
        let pcrs: Vec<(usize, Vec<u8>)> = map
            .remove("pcrs")
            .and_then(|value| value.as_map().cloned())
            .and_then(|pairs| {
                if !(1..=32).contains(&pairs.len()) {
                    return None;
                }
                let mut pcrs = Vec::with_capacity(pairs.len());
                for (key, value) in pairs.into_iter() {
                    let index = key
                        .as_integer()
                        .and_then(|n| usize::try_from(n).ok())
                        .filter(|n| (0..32).contains(n))?;
                    let bytes = value
                        .as_bytes()
                        .filter(|bs| [32, 48, 64].contains(&bs.len()))?;
                    pcrs.push((index, bytes.to_vec()))
                }
                Some(pcrs)
            })
            .ok_or(NitroError::InvalidAttestationDoc)?;

        fn into_valid_cert_bytes(value: Value) -> Option<Vec<u8>> {
            value
                .as_bytes()
                .map(|b| b.to_vec())
                .filter(|bs| (1..=1024).contains(&bs.len()))
        }

        let certificate = map
            .remove("certificate")
            .and_then(into_valid_cert_bytes)
            .ok_or(NitroError::InvalidAttestationDoc)?;

        let cabundle = map
            .remove("cabundle")
            .and_then(|value| value.as_array().cloned())
            .and_then(|vals| {
                let certs: Vec<_> = vals.into_iter().filter_map(into_valid_cert_bytes).collect();
                if certs.is_empty() {
                    return None;
                }
                Some(certs)
            })
            .ok_or(NitroError::InvalidAttestationDoc)?;

        fn into_valid_optional_bytes(
            value: Value,
            expected_length: usize,
        ) -> Result<Vec<u8>, NitroError> {
            match value.as_bytes() {
                Some(bytes) if bytes.len() <= expected_length => Ok(bytes.to_vec()),
                None | Some(_) => Err(NitroError::InvalidAttestationDoc),
            }
        }

        let public_key = map
            .remove("public_key") // option<value>
            .map(|value| into_valid_optional_bytes(value, 1024))
            .transpose()?;

        let user_data = map
            .remove("user_data")
            .map(|value| into_valid_optional_bytes(value, 512))
            .transpose()?;

        let nonce = map
            .remove("nonce")
            .map(|value| into_valid_optional_bytes(value, 10))
            .transpose()?;

        Ok(AttestationDoc {
            module_id: module_id.to_string(),
            digest: digest.to_string(),
            timestamp,
            pcrs,
            certificate,
            cabundle,
            public_key,
            user_data,
            nonce,
        })
    }

    fn verified_cert(&self, now: SystemTime) -> Result<X509, NitroError> {
        let mut context = X509StoreContext::new()?;
        let certificate = X509::from_der(&self.certificate)?;
        let mut stack = stack::Stack::<X509>::new()?;
        for der in self.cabundle.iter() {
            let cert = X509::from_der(der)?;
            stack.push(cert)?;
        }
        let stack = stack;
        let trust = {
            let root = X509::from_pem(ROOT_CERTIFICATE_PEM)?;
            let mut builder = X509StoreBuilder::new()?;
            builder.param_mut().set_time(
                now.duration_since(SystemTime::UNIX_EPOCH)
                    .expect("current time is after 1970")
                    .as_secs()
                    .try_into()
                    .expect("haven't yet overflowed time_t"),
            );
            builder.add_cert(root)?;
            builder.build()
        };
        let is_valid = context.init(&trust, &certificate, &stack, |ctx| ctx.verify_cert())?;
        if !is_valid {
            let message = context.verify_result().unwrap_err().to_string();
            return Err(NitroError::InvalidCertificate(message));
        }
        Ok(certificate)
    }

    fn validate_pcrs(&self, expected_pcrs: &PcrMap) -> Result<(), NitroError> {
        let mut is_match = true;
        for (index, pcr) in self.pcrs.iter() {
            is_match &= expected_pcrs
                .get(index)
                .map(|expected| expected.ct_eq(pcr).into())
                // if the index is missing from the expected_pcrs we do not check it
                .unwrap_or(true);
        }
        if is_match {
            Ok(())
        } else {
            Err(NitroError::InvalidPcrs)
        }
    }
}
