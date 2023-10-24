// SPDX-FileCopyrightText: 2022 Profian Inc. <opensource@profian.com>
// SPDX-License-Identifier: Apache-2.0 OR MIT

// use core::fmt::Display;
// use core::{convert::Infallible, str::FromStr};

// use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
// use jose_b64::stream::Error;

// use crate::{Flattened, General, Jws, Signature};

use alloc::string::String;
use alloc::{vec::Vec, format};
use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};

use crate::Error;

#[derive(Debug, PartialEq)]
pub struct CompactComponents<'a> {
    pub header: &'a str,
    pub payload: &'a str,
    pub signature: &'a str,
}

impl<'a> CompactComponents<'a> {
    pub fn decode(s: &'a str) -> Result<Self, Error> {
        let mut iter = s.split('.');

        let header = iter.next().ok_or(Error::CompactWrongFormat)?;
        let payload = iter.next().ok_or(Error::CompactWrongFormat)?;
        let signature = iter.next().ok_or(Error::CompactWrongFormat)?;

        if iter.next().is_some() {
            return Err(Error::CompactWrongFormat);
        }

        Ok(Self { header, payload, signature })
    }

    pub fn encode(&self) -> String {
        format!("{}.{}.{}", self.header, self.payload, self.signature)
    }

    pub fn header_b64_decoded(&self) -> Result<Vec<u8>, jose_b64::base64ct::Error> {
        Base64UrlUnpadded::decode_vec(self.header)
    }

    pub fn payload_b64_decoded(&self) -> Result<Vec<u8>, jose_b64::base64ct::Error> {
        Base64UrlUnpadded::decode_vec(self.payload)
    }

    pub fn signature_b64_decoded(&self) -> Result<Vec<u8>, jose_b64::base64ct::Error> {
        Base64UrlUnpadded::decode_vec(self.signature)
    }
}
