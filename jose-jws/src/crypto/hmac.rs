use alloc::vec::Vec;
use core::{marker::PhantomData, ops::Deref};

use crypto_common::{BlockSizeUser, generic_array::GenericArray};
use digest::{Digest, Mac, CtOutput};
use hmac::SimpleHmac;
use subtle::ConstantTimeEq;
use jose_b64::serde::Secret;
use jose_jwk::{Jwk, Key};

use crate::Error;
use super::{SigningKey, Signer, VerifyingKey, Verifier};

pub struct HmacKey<'a, D: Digest + BlockSizeUser> {
    k: &'a Secret,
    _d: PhantomData<D>,
}

impl<'a, D> HmacKey<'a, D>
where
    D: Digest + BlockSizeUser
{
    pub fn new(key: &'a Jwk) -> Result<Self, Error> {
        if let Key::Oct(ref oct) = key.key {
            Ok(HmacKey { k: &oct.k, _d: PhantomData })
        } else {
            Err(Error::KeyTypeDoesNotMatchAlg)
        }
    }
}

impl<'a, D: Digest + BlockSizeUser> SigningKey<'a> for HmacKey<'a, D> {
    type StartError = Error;
    type Signer = HmacSigner<D>;

    fn signer(
        &'a self
    ) -> Result<Self::Signer, Self::StartError> {
        Ok(HmacSigner {
            hmac: SimpleHmac::new(self.k.deref().deref().deref().into()),
        })
    }
}

pub struct HmacSigner<D: Digest + BlockSizeUser> {
    hmac: SimpleHmac<D>,
}

impl<D: Digest + BlockSizeUser> jose_b64::stream::Update for HmacSigner<D> {
    type Error = Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.hmac.update(chunk.as_ref());

        Ok(())
    }
}

impl<D: Digest + BlockSizeUser> Signer for HmacSigner<D> {
    type FinishError = Error;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        let computed = self.hmac.finalize();

        Ok(computed.into_bytes().to_vec())
    }
}

impl<'a, D> VerifyingKey<'a> for HmacKey<'a, D>
where
    D: Digest + BlockSizeUser,
{
    type StartError = Error;
    type Verifier = HmacVerifier<'a, D>;
    fn verifier(&'a self, signature: &'a [u8]) -> Result<Self::Verifier, Self::StartError> {
        if signature.len() != <D as Digest>::output_size() {
            return Err(Error::SignatureCheckFailed)
        }
        Ok(HmacVerifier {
            signature,
            hmac: SimpleHmac::new(self.k.deref().deref().deref().into()),
        })
    }
}

pub struct HmacVerifier<'a, D>
where
    D: Digest + BlockSizeUser,
{
    signature: &'a [u8],
    hmac: SimpleHmac<D>,
}

impl<'a, D> jose_b64::stream::Update for HmacVerifier<'a, D>
where
    D: Digest + BlockSizeUser,
{
    type Error = Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        self.hmac.update(chunk.as_ref());

        Ok(())
    }
}

impl<'a, D> Verifier<'a> for HmacVerifier<'a, D>
where
    D: Digest + BlockSizeUser,
{
    type FinishError = Error;

    fn finish(self) -> Result<(), Self::FinishError> {
        let computed = self.hmac.finalize();

        let signature: CtOutput<SimpleHmac<D>> = CtOutput::from(GenericArray::from_slice(self.signature));

        if bool::from(computed.ct_eq(&signature)) {
            Ok(())
        } else {
            Err(Error::SignatureCheckFailed)
        }
    }
}