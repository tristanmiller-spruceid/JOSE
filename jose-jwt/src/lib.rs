#![cfg_attr(not(test), no_std)]
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

use alloc::string::String;
use alloc::borrow::ToOwned;

use jose_claims::SecondsNumericDate;
use jose_jwa::Signing;
use jose_jwk::Jwk;

use serde::{de::DeserializeOwned, Deserialize, Serialize};

const JWT_TYP: &'static str = "JWT";

#[derive(Debug)]
pub enum Error {
    UnknownAlgorithm,
    AlgorithmAndKeyMismatch,
    WrongTyp,
    InvalidCompactFormat,
    SerializingHeader(serde_json::Error),
    SerializingPayload(serde_json::Error),
    DeserializingClaims(serde_json::Error),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ClaimSet<OtherClaims = (), Date = SecondsNumericDate>
where
{
    pub iss: Option<String>,

    pub sub: Option<String>,

    pub aud: Option<String>,

    pub exp: Option<Date>,

    pub nbf: Option<Date>,

    pub iat: Option<Date>,

    pub jti: Option<String>,

    #[serde(flatten)]
    pub other_claims: OtherClaims,
}

impl<OtherClaims, Date> Default for ClaimSet<OtherClaims, Date>
where
    OtherClaims: Default
{
    fn default() -> Self {
        ClaimSet {
            iss: None,
            sub: None,
            aud: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            other_claims: Default::default(),
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct Jwt<Claims = (), HeaderExtra = ()> {
    pub header: Header<HeaderExtra>,
    pub claims: ClaimSet<Claims>,
}

#[derive(Debug, PartialEq)]
pub enum Header<HeaderExtra> {
    Jws(jose_jws::Header<HeaderExtra>),
    Jwe,
}

impl<HeaderExtra> Header<HeaderExtra> {
    pub fn typ(&self) -> Option<&str> {
        match self {
            Header::Jws(header) => header.typ.as_ref().map(|s| s.as_str()),
            Header::Jwe => todo!(),
        }
    }
}

const NUM_ELEMENTS_FOR_JWS: usize = 3;
const NUM_ELEMENTS_FOR_JWE: usize = 5;

impl<Claims, HeaderExtra> Jwt<Claims, HeaderExtra> {
    pub fn decode_verify(jwt: &str, key: &Jwk) -> Result<Self, Error>
    where
        HeaderExtra: DeserializeOwned,
        Claims: DeserializeOwned,
    {
        let num_elements = jwt.split('.').count();

        let (payload, header) = match num_elements {
            NUM_ELEMENTS_FOR_JWS => {
                let (payload, header) = jose_jws::decode_verify_compact(jwt, key).unwrap();
    
                (payload, Header::Jws(header))
            }
            NUM_ELEMENTS_FOR_JWE => {
                todo!("jwe decode verify")
            }
            _ => {
                return Err(Error::InvalidCompactFormat)
            }
        };

        if header.typ() != Some(JWT_TYP) {
            return Err(Error::WrongTyp);
        }
    
        let claims = serde_json::from_slice(&payload)
            .map_err(|err| Error::DeserializingClaims(err))?;
    
        Ok(Self {
            header,
            claims,
        })
    }

    pub fn encode(&self, key: &Jwk) -> Result<String, Error>
    where
        HeaderExtra: Serialize,
        Claims: Serialize,
    {
        let payload = serde_json::to_vec(&self.claims).unwrap();
        Ok(match self.header {
            Header::Jws(ref header) => {
                jose_jws::encode_compact(header, &payload, key).unwrap()
            }
            Header::Jwe => todo!(),
        })
    }
}

impl<Claims, HeaderExtra> Jwt<Claims, HeaderExtra>
where
    HeaderExtra: Default
{
    pub fn build_jws(signing: Signing, claims: ClaimSet<Claims>) -> Self {
        Self {
            header: Header::Jws(jose_jws::Header {
                typ: Some(JWT_TYP.to_owned()),
                alg: Some(signing),
                ..Default::default()
            }),
            claims,
        }
    }
}

// pub fn encode_signed<Claims: Serialize>(
//     algorithm: Signing,
//     claims: &Claims,
//     key: &Key,
// ) -> Result<String, Error> {
//     encode_signed_with_key_and_algo(claims, ValidatedKeyAndAlgo::validate(algorithm, key)?)
// }

// pub fn encode_none<Claims: Serialize>(
//     claims: &Claims,
// ) -> Result<String, Error> {
//     encode_signed_with_key_and_algo(claims, ValidatedKeyAndAlgo::None)
// }

// fn encode_signed_with_key_and_algo<Claims: Serialize>(
//     claims: &Claims,
//     key_and_algo: ValidatedKeyAndAlgo,
// ) -> Result<String, Error> {
//     let header = Protected {
//         oth: Unprotected {
//             alg: Some(key_and_algo.signing()),
//             typ: Some(JWT_TYP.to_owned()),
//             ..Default::default()    
//         },
//         ..Default::default()
//     };
    
//     encode_signed_with_header_key_and_algo(header, claims, key_and_algo)
// }

// pub fn encode_signed_with_header<Claims: Serialize>(
//     header: Unprotected,
//     claims: &Claims,
//     key: &Key,
// ) -> Result<String, Error> {
//     // validate header
//     todo!()
// }

// fn encode_signed_with_header_key_and_algo<Claims: Serialize>(
//     _header: Protected,
//     claims: &Claims,
//     key_and_algo: ValidatedKeyAndAlgo<'_>,
// ) -> Result<String, Error> {
//     let payload_str = serde_json::to_string(claims)
//         .map_err(|err| Error::SerializingPayload(err))?;

//     // let flattened = Flattened {
//     //     payload: Some(Bytes::from(payload_str.as_bytes())),
//     //     protected: Some(header),
//     // };

//     use ValidatedKeyAndAlgo::*;
//     let payload_bytes: Vec<u8> = match key_and_algo {
//         Hs256(_) => todo!(),
//         None => vec![],
//     };

//     let signature_bytes = {

//     };
//     todo!()
// }

// #[derive(Debug)]
// enum ValidatedKeyAndAlgo<'a> {
//     Hs256(&'a Secret),

//     None,
// }

// impl<'a> ValidatedKeyAndAlgo<'a> {
//     fn validate(algorithm: Signing, key: &'a Key) -> Result<Self, Error> {
//         match (algorithm, key) {
//             (Signing::Hs256, Key::Oct(secret)) => Ok(Self::Hs256(&secret.k)),
//             (Signing::Hs256, _) => Err(Error::AlgorithmAndKeyMismatch),

//             _ => Err(Error::UnknownAlgorithm),
//         }
//     }

//     fn signing(&self) -> Signing {
//         use ValidatedKeyAndAlgo::*;

//         match self {
//             Hs256(_) => Signing::Hs256,
//             None => Signing::Null,
//         }
//     }
// }

// #[cfg(test)]
// mod tests {
//     #[test]
//     pub fn validate_key_and_algo() {

//     }
// }