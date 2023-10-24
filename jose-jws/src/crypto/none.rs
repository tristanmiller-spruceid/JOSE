use alloc::{vec, vec::Vec};

use crate::Error;
use super::{SigningKey, Signer, VerifyingKey, Verifier};

pub struct NoneKey;

impl NoneKey {
    pub fn new() -> Result<Self, Error> {
        Ok(NoneKey {})
    }
}

impl<'a> SigningKey<'a> for NoneKey {
    type StartError = Error;
    type Signer = NoneSigner;

    fn signer(&'a self) -> Result<Self::Signer, Self::StartError> {
        Ok(NoneSigner {})
    }
}

pub struct NoneSigner;

impl jose_b64::stream::Update for NoneSigner {
    type Error = Error;

    fn update(&mut self, _chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl Signer for NoneSigner {
    type FinishError = Error;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        Ok(vec![])
    }
}

impl<'a> VerifyingKey<'a> for NoneKey {
    type StartError = Error;
    type Verifier = NoneVerifier;

    fn verifier(&'a self, signature: &'a [u8]) -> Result<Self::Verifier, Self::StartError> {
        Ok(NoneVerifier {
            was_empty: signature.is_empty(),
        })
    }
}

pub struct NoneVerifier {
    was_empty: bool,
}

impl jose_b64::stream::Update for NoneVerifier {
    type Error = Error;

    fn update(&mut self, _chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        Ok(())
    }
}

impl<'a> Verifier<'a> for NoneVerifier {
    type FinishError = Error;

    fn finish(self) -> Result<(), Self::FinishError> {
        if self.was_empty {
            Ok(())
        } else {
            todo!()
        }
    }
}