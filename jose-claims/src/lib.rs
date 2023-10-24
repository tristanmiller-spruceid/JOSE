#![cfg_attr(not(test), no_std)]

extern crate alloc;

use core::fmt::Debug;
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, PartialEq, PartialOrd)]
pub struct SecondsNumericDate(u32);

impl From<u32> for SecondsNumericDate {
    fn from(value: u32) -> Self {
        SecondsNumericDate(value)
    }
}

#[derive(Debug, PartialEq, PartialOrd)]
pub struct FloatingNumericDate(f64);

pub trait ExpirationValidity<T>
    where T: PartialOrd
{
    fn exp(&self) -> &Option<T>;
    fn nbf(&self) -> &Option<T>;
    fn iat(&self) -> &Option<T>;

    fn time_valid(&self, now: T) -> bool {
        if let Some(exp) = self.exp() {
            if &now > exp {
                return false;
            }
        }

        if let Some(nbf) = self.nbf() {
            if &now < nbf {
                return false;
            }
        }

        if let Some(iat) = self.iat() {
            if iat > &now {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHeader {
        exp: Option<u32>,
        nbf: Option<u32>,
        iat: Option<u32>,
    }

    impl ExpirationValidity<u32> for TestHeader {
        fn exp(&self) -> &Option<u32> {
            &self.exp
        }

        fn iat(&self) -> &Option<u32> {
            &self.iat
        }

        fn nbf(&self) -> &Option<u32> {
            &self.nbf
        }
    }

    #[test]
    fn none_always_valid() {
        assert!(
            TestHeader {
                exp: None,
                nbf: None,
                iat: None,
            }.time_valid(0)
        )
    }

    #[test]
    fn exp_past_now_valid() {
        assert!(
            TestHeader {
                exp: Some(42),
                nbf: None,
                iat: None,
            }.time_valid(36)
        )
    }

    #[test]
    fn exp_at_now_invalid() {
        assert!(
            !TestHeader {
                exp: Some(42),
                nbf: None,
                iat: None,
            }.time_valid(54)
        )
    }

    #[test]
    fn nbf_at_now_valid() {

    }
}
