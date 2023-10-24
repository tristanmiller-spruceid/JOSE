use jose_jwa::Signing;
use jose_jwk::Jwk;
use jose_jwt::{Jwt, ClaimSet};
use serde::{Deserialize, Serialize};

const JWT: &str = concat!(
    "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ".",
    "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
);

fn test_key() -> Jwk {
    serde_json::from_value(serde_json::json!({
        "kty": "oct",
        "k": "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    }))
    .unwrap()
}

#[derive(Debug, Default, PartialEq, Deserialize, Serialize)]
struct RootClaim {
    #[serde(rename = "http://example.com/is_root")]
    is_root: bool,
}

type RfcJwt = Jwt::<RootClaim>;

#[test]
fn decode() {
    let jwt = RfcJwt::decode_verify(JWT, &test_key()).unwrap();

    eprintln!("{:?}", jwt);

    assert_eq!(jwt.claims, ClaimSet {
        iss: Some("joe".to_owned()),
        exp: Some(1300819380.into()),
        other_claims: RootClaim {
            is_root: true,
        },
        ..Default::default()
    })
}

#[test]
fn full_pathway() {
    let built = RfcJwt::build_jws(Signing::Hs256, ClaimSet {
        iss: Some("joe".to_owned()),
        exp: Some(1300819380.into()),
        other_claims: RootClaim {
            is_root: true,
        },
        ..Default::default()
    });

    let jwt = built.encode(&test_key()).unwrap();

    let decoded = RfcJwt::decode_verify(&jwt, &test_key()).unwrap();

    assert_eq!(built, decoded)
}