use alloc::string::String;
use alloc::vec::Vec;

use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use jose_jwa::Signing;
use jose_jwk::Jwk;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384, Sha512};

use crate::crypto::ecdsa::EcdsaSigningKey;
use crate::crypto::{SigningKey, Signer, Verifier, VerifyingKey, ecdsa::EcdsaVerifyingKey, hmac::HmacKey};
use crate::{Error, Header};

#[derive(Debug)]
pub struct Signature<HeaderOther = (), UnprotectedOther = ()> {
    pub protected: Header<HeaderOther>,

    pub unprotected: Option<Header<UnprotectedOther>>,

    pub signature: Vec<u8>,
}

impl<HeaderOther> Signature<HeaderOther> {
    pub fn verify(&self, raw_protected: &[u8], raw_payload: &[u8], key: &Jwk) -> Result<(), Error> {
        let alg = self.alg()?;

        use Signing::*;
        match alg {
            Es256 => {
                EcdsaVerifyingKey::<p256::NistP256, Sha256>::new(key)?
                    .verifier(&self.signature)?
                    .verify(raw_protected, raw_payload)
            }
            Es384 => {
                EcdsaVerifyingKey::<p384::NistP384, Sha384>::new(key)?
                    .verifier(&self.signature)?
                    .verify(raw_protected, raw_payload)
            }
            // Es512 => {
            //     EcdsaVerifyingKey::<p521::NistP521, Sha512>::new(key)?
            //         .verifier(&self.signature)?
            //         .verify(raw_protected, raw_payload)
            // }

            Hs256 => {
                HmacKey::<Sha256>::new(key)?
                    .verifier(&self.signature)?
                    .verify(raw_protected, raw_payload)
            }
            Hs384 => {
                HmacKey::<Sha384>::new(key)?
                    .verifier(&self.signature)?
                    .verify(raw_protected, raw_payload)
            }
            Hs512 => {
                HmacKey::<Sha512>::new(key)?
                    .verifier(&self.signature)?
                    .verify(raw_protected, raw_payload)
            }
            other => todo!("Handle unknown alg: {:?}", other)
        }
    }

    pub fn alg(&self) -> Result<Signing, Error> {
        self.protected.alg.ok_or(Error::MissingAlg)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EncodedSignature {
    pub protected: String,
    pub unprotected: Option<String>,
    pub signature: String,
}

impl EncodedSignature {
    pub fn sign<HeaderOther, UnprotectedOther>(
        protected: &Header<HeaderOther>,
        unprotected: Option<&Header<UnprotectedOther>>,
        payload: &str,
        key: &Jwk,
    ) -> Result<Self, Error>
    where
        HeaderOther: Serialize,
        UnprotectedOther: Serialize,
    {
        let alg = protected.alg.ok_or(Error::MissingAlg)?;
    
        let header_json = serde_json::to_string(protected).unwrap();
        let header_b64 = Base64UrlUnpadded::encode_string(header_json.as_bytes());

        let sig_bytes: Vec<u8> = match alg {
            Signing::Es256 => {
                EcdsaSigningKey::<p256::NistP256, Sha256>::new(key)?
                    .signer()?
                    .sign(&header_b64, payload)?
            }
            Signing::Es384 => {
                EcdsaSigningKey::<p384::NistP384, Sha384>::new(key)?
                    .signer()?
                    .sign(&header_b64, payload)?
            }

            Signing::Hs256 => {
                HmacKey::<Sha256>::new(key)?
                    .signer()?
                    .sign(&header_b64, payload)?
            }
            Signing::Hs384 => {
                HmacKey::<Sha384>::new(key)?
                    .signer()?
                    .sign(&header_b64, payload)?
            }
            Signing::Hs512 => {
                HmacKey::<Sha512>::new(key)?
                    .signer()?
                    .sign(&header_b64, payload)?
            }
            _ => {
                return Err(Error::UnimplementedAlg(alg))
            }
        };

        let unprotected_b64 = match unprotected {
            None => None,
            Some(unprot) => {
                let unprot_json = serde_json::to_string(unprot).unwrap();
                let unprot_b64 = Base64UrlUnpadded::encode_string(unprot_json.as_bytes());
                Some(unprot_b64)
            }
        };

        Ok(EncodedSignature {
            protected: header_b64,
            unprotected: unprotected_b64,
            signature: Base64UrlUnpadded::encode_string(&sig_bytes),
        })
    }
}
