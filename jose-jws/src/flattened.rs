use alloc::string::String;
use jose_b64::serde::Bytes;
use serde::{Deserialize, Serialize};

use crate::{Error, Header};

#[derive(Debug, Deserialize, Serialize)]
pub struct Flattened<ProtectedHeaderExtra = (), HeaderExtra = ()> {
    pub payload: Bytes,

    pub protected: Option<Header<ProtectedHeaderExtra>>,

    pub unprotected: Option<Header<HeaderExtra>>,

    pub signature: Option<Bytes>,
}

impl Flattened {
    pub fn from_compact(compact_str: &str) -> Result<Self, Error> {
        todo!()
    }

    pub fn to_compact(&self) -> Result<String, Error> {
        todo!()
    }
}