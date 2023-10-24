// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

#![no_std]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![doc = include_str!("../README.md")]
#![doc(
    html_logo_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg",
    html_favicon_url = "https://raw.githubusercontent.com/RustCrypto/media/6ee8e381/logo.svg"
)]
#![forbid(unsafe_code)]
#![warn(
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    missing_docs,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]

extern crate alloc;

pub mod crypto;

mod compact;
mod flattened;
mod head;
mod signature;

pub use head::{Header, Protected, Unprotected};
use jose_b64::base64ct::{Base64Unpadded, Encoding};
use jose_jwa::Signing;
use signature::EncodedSignature;
pub use signature::Signature;

use alloc::string::String;
use alloc::vec::Vec;

use jose_jwk::Jwk;
use serde::{Serialize, de::DeserializeOwned};

pub fn decode_verify_compact<HeaderOther>(
    compact: &str,
    key: &Jwk,
) -> Result<(Vec<u8>, Header<HeaderOther>), Error>
where
    HeaderOther: DeserializeOwned
{
    let compact = compact::CompactComponents::decode(compact)?;

    let raw_protected = compact.header_b64_decoded().unwrap();

    let protected: Header<HeaderOther> = serde_json::from_slice(&raw_protected)
        .map_err(|err| Error::ProtectedHeaderParseError(err))?;

    let payload = if !protected.b64 {
        todo!("Handle rfc 7797")
    } else {
        compact.payload_b64_decoded().unwrap()
    };

    let signature_bytes = compact.signature_b64_decoded().unwrap();

    let signature = Signature::<HeaderOther, ()> {
        protected,
        unprotected: None,
        signature: signature_bytes,
    };

    signature.verify(compact.header.as_bytes(), compact.payload.as_bytes(), key)?;

    Ok((payload, signature.protected))
}

pub fn encode_compact<HeaderOther>(
    header: &Header<HeaderOther>,
    payload: &[u8],
    key: &Jwk,
) -> Result<String, Error>
where
    HeaderOther: Serialize
{
    let payload = encode_payload(&header, payload)?;

    let signature: EncodedSignature = EncodedSignature::sign::<HeaderOther, ()>(
        header,
        None,
        &payload,
        key,
    )?;

    let compact = compact::CompactComponents {
        header: &signature.protected,
        payload: &payload,
        signature: &signature.signature,
    };

    Ok(compact.encode())
}

fn encode_payload<HeaderOther>(header: &Header<HeaderOther>, payload: &[u8]) -> Result<String, Error> {
    if !header.b64 {
        todo!("Handle rfc 7797")
    } else {
        Ok(Base64Unpadded::encode_string(payload))
    }
}

// /// A JSON Web Signature representation
// #[derive(Clone, Debug, Serialize, Deserialize)]
// #[non_exhaustive]
// #[allow(clippy::large_enum_variant)]
// #[serde(untagged)]
// pub enum Jws {
//     /// General Serialization. This is
//     General(General),

//     /// Flattened Serialization
//     Flattened(Flattened),
// }

// impl From<General> for Jws {
//     fn from(value: General) -> Self {
//         Jws::General(value)
//     }
// }

// impl From<Flattened> for Jws {
//     fn from(value: Flattened) -> Self {
//         Jws::Flattened(value)
//     }
// }

// /// General Serialization
// ///
// /// This is the usual JWS form, which allows multiple signatures to be
// /// specified.
// ///
// /// ```json
// /// {
// ///     "payload":"<payload contents>",
// ///     "signatures":[
// ///      {"protected":"<integrity-protected header 1 contents>",
// ///       "header":<non-integrity-protected header 1 contents>,
// ///       "signature":"<signature 1 contents>"},
// ///      ...
// ///      {"protected":"<integrity-protected header N contents>",
// ///       "header":<non-integrity-protected header N contents>,
// ///       "signature":"<signature N contents>"}]
// /// }
// /// ```
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct General {
//     /// The payload of the signature.
//     pub payload: Option<Bytes>,

//     /// The signatures over the payload.
//     pub signatures: Vec<Signature>,
// }

// impl From<Flattened> for General {
//     fn from(value: Flattened) -> Self {
//         Self {
//             payload: value.payload,
//             signatures: vec![value.signature],
//         }
//     }
// }

/// Flattened Serialization
///
/// This is similar to the general serialization but is more compact, only
/// supporting one signature.
///
/// ```json
/// {
///     "payload":"<payload contents>",
///     "protected":"<integrity-protected header contents>",
///     "header":<non-integrity-protected header contents>,
///     "signature":"<signature contents>"
/// }
/// ```
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct Flattened {
//     /// The payload of the signature.
//     pub payload: Option<Bytes>,

//     /// The signature over the payload.
//     #[serde(flatten)]
//     pub signature: Signature,
// }

// /// A Signature
// #[derive(Clone, Debug, Serialize, Deserialize)]
// pub struct Signature {
//     /// The JWS Unprotected Header
//     pub header: Option<Unprotected>,

//     /// The JWS Protected Header
//     pub protected: Option<Json<Protected>>,

//     /// The Signature Bytes
//     pub signature: Bytes,
// }

#[derive(Debug)]
pub enum Error {
    CompactWrongFormat,
    MissingAlg,
    KeyTypeDoesNotMatchAlg,
    SignatureCheckFailed,
    UnimplementedAlg(Signing),
    RngRequriedToSign,
    WrongKeyTypeForAlg,
    ProtectedHeaderParseError(serde_json::Error),
}
