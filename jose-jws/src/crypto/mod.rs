// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

//! JWS Cryptographic Implementation

pub mod ecdsa;
pub mod hmac;
pub mod none;

use alloc::vec::Vec;

use jose_b64::stream::Update;

pub struct Signature;
pub struct Protected;
pub struct Unprotected;

/// Signature creation state
pub trait Signer: Update + Sized {
    #[allow(missing_docs)]
    type FinishError: From<Self::Error>;

    /// Finish processing payload and create the signature.
    fn finish(self) -> Result<Vec<u8>, Self::FinishError>;

    fn sign(self, header_b64: &str, payload: &str) -> Result<Vec<u8>, Self::FinishError> {
        self.chain(header_b64.as_bytes())?
            .chain(b".")?
            .chain(payload.as_bytes())?
            .finish()
    }
}

/// A signature creation key
pub trait SigningKey<'a> {
    #[allow(missing_docs)]
    type StartError: From<<Self::Signer as Update>::Error>;

    /// The state object used during signing.
    type Signer: Signer;

    /// Begin the signature creation process.
    fn signer(&'a self) -> Result<Self::Signer, Self::StartError>;
}

/// Signature verification state
pub trait Verifier<'a>: Update + Sized {
    #[allow(missing_docs)]
    type FinishError: From<Self::Error>;

    /// Finish processing payload and verify the signature.
    fn finish(self) -> Result<(), Self::FinishError>;

    fn verify(self, raw_protected: &[u8], raw_payload: &[u8]) -> Result<(), Self::FinishError> {
        self.chain(raw_protected)?
        .chain(b".")?
        .chain(raw_payload)?
        .finish()
    }
}

impl<'a, T: Verifier<'a>> Verifier<'a> for Vec<T>
where
    T::FinishError: Default,
{
    type FinishError = T::FinishError;

    fn finish(self) -> Result<(), Self::FinishError> {
        let mut last = T::FinishError::default();

        for x in self {
            match x.finish() {
                Ok(()) => return Ok(()),
                Err(e) => last = e,
            }
        }

        Err(last)
    }
}

/// A signature verification key
pub trait VerifyingKey<'a> {
    #[allow(missing_docs)]
    type StartError: From<<Self::Verifier as Update>::Error>;

    /// The state object used during signing.
    type Verifier: Verifier<'a>;

    /// Begin the signature verification process.
    fn verifier(&'a self, signature: &'a [u8]) -> Result<Self::Verifier, Self::StartError>;
}
