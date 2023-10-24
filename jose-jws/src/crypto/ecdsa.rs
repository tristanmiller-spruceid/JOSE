use alloc::vec::Vec;
use core::{ops::Deref, marker::PhantomData};
use crypto_common::generic_array::ArrayLength;
use ecdsa::{PrimeCurve, elliptic_curve::{CurveArithmetic, Scalar, FieldBytesSize, sec1::{ModulusSize, FromEncodedPoint, ToEncodedPoint}, AffinePoint}, hazmat::{SignPrimitive, VerifyPrimitive}, SignatureSize, EncodedPoint, Signature};
use ecdsa::hazmat::DigestPrimitive;
use ecdsa::elliptic_curve::ops::Invert;
use digest::{Digest, FixedOutput};
use signature::{DigestSigner, DigestVerifier};
use jose_b64::stream::Update;
use jose_jwk::{Jwk, Key};
use subtle::CtOption;

use super::{VerifyingKey, Verifier, SigningKey, Signer};

use crate::Error;

pub struct EcdsaVerifyingKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    key: ecdsa::VerifyingKey<C>,

    _spoopy: PhantomData<D>,
}

impl<C, D> EcdsaVerifyingKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
    C::FieldBytesSize: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    pub fn new(key: &Jwk) -> Result<Self, Error> {
        let (x, y) = if let Key::Ec(ref key) = key.key {
            (&key.x, &key.y)
        } else {
            return Err(Error::WrongKeyTypeForAlg)
        };

        let point = EncodedPoint::<C>::from_affine_coordinates(
            x.deref().deref().deref().into(),
            y.deref().deref().deref().into(),
            false,
        );

        let key = ecdsa::VerifyingKey::<C>::from_encoded_point(&point).unwrap();

        Ok(Self {
            key,
            _spoopy: Default::default(),
        })
    }
}

impl<'a, C, D> VerifyingKey<'a> for EcdsaVerifyingKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type StartError = Error;

    type Verifier = EcdsaVerifier<'a, C, D>;

    fn verifier(&'a self, signature: &'a [u8]) -> Result<Self::Verifier, Self::StartError> {
        Ok(EcdsaVerifier {
            key: self.key.clone(),
            digest: D::new(),
            signature,
        })
    }
}

pub struct EcdsaVerifier<'a, C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    key: ecdsa::VerifyingKey<C>,

    digest: D,

    signature: &'a [u8],
}

impl<'a, C, D> Update for EcdsaVerifier<'a, C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        <D as Digest>::update(&mut self.digest, chunk);

        Ok(())
    }
}

impl<'a, C, D> Verifier<'a> for EcdsaVerifier<'a, C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    AffinePoint<C>: VerifyPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type FinishError = Error;

    fn finish(self) -> Result<(), Self::FinishError> {
        let sig = Signature::<C>::from_bytes(self.signature.into()).unwrap();

        match self.key.verify_digest(self.digest, &sig) {
            Ok(()) => Ok(()),
            Err(err) => todo!("{err:?}")
        }
    }
}

pub struct EcdsaSigningKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    key: ecdsa::SigningKey<C>,

    _spoopy: PhantomData<D>,
}

impl<C, D> EcdsaSigningKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    pub fn new(key: &Jwk) -> Result<Self, Error> {
        let private_key = if let Key::Ec(ref key) = key.key {
            key.d.as_ref()
        } else {
            return Err(Error::WrongKeyTypeForAlg)
        };

        let key = if let Some(key) = private_key {
            ecdsa::SigningKey::<C>::from_slice(key.deref()).unwrap()
        } else {
            todo!()
        };

        Ok(EcdsaSigningKey {
            key,
            _spoopy: Default::default(),
        })
    } 
}

impl<'a, C, D> SigningKey<'a> for EcdsaSigningKey<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type StartError = Error;

    type Signer = EcdsaSigner<C, D>;

    fn signer(&'a self) -> Result<Self::Signer, Self::StartError> {
        Ok(EcdsaSigner {
            key: self.key.clone(),
            digest: D::new(),
        })
    }
}

pub struct EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    key: ecdsa::SigningKey<C>,
    digest: D,
}

impl<C, D> Update for EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type Error = Error;

    fn update(&mut self, chunk: impl AsRef<[u8]>) -> Result<(), Self::Error> {
        <D as Digest>::update(&mut self.digest, chunk);

        Ok(())
    }
}

impl<C, D> Signer for EcdsaSigner<C, D>
where
    C: PrimeCurve + CurveArithmetic + DigestPrimitive,
    D: Digest + FixedOutput<OutputSize = FieldBytesSize<C>>,
    Scalar<C>: Invert<Output = CtOption<Scalar<C>>> + SignPrimitive<C>,
    SignatureSize<C>: ArrayLength<u8>,
{
    type FinishError = Error;

    fn finish(self) -> Result<Vec<u8>, Self::FinishError> {
        let sig: Signature<C> = self.key.try_sign_digest(self.digest).unwrap();

        Ok(sig.to_vec())
    }
}
