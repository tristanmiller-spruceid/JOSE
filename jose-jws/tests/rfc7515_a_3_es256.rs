use jose_jwa::Signing;
use jose_jwk::Jwk;
use jose_jws::{decode_verify_compact, encode_compact, Header};

const COMPACT_JWS: &str = concat!(
    "eyJhbGciOiJFUzI1NiJ9",
    ".",
    "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt",
    "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ",
    ".",
    "DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSA",
    "pmWQxfKTUJqPP3-Kg6NU1Q"
);

fn test_key() -> Jwk {
    serde_json::from_value(serde_json::json!({
        "kty":"EC",
        "crv":"P-256",
        "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
   }))
   .unwrap()
}

const PAYLOAD: &[u8] = b"{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

#[test]
fn decode() {
    let (payload, header) = decode_verify_compact::<()>(COMPACT_JWS, &test_key()).unwrap();

    assert_eq!(&payload, PAYLOAD);

    assert_eq!(header, Header::<()> {
        alg: Some(Signing::Es256),
        ..Default::default()
    });
}

#[test]
fn full_pathway() {
    let compact = encode_compact(
        &Header::<()> {
            alg: Some(Signing::Es256),
            ..Default::default()
        },
        PAYLOAD,
        &test_key(),
    ).unwrap();

    let (decoded_payload, decoded_header) = decode_verify_compact(&compact, &test_key()).unwrap();

    assert_eq!(&decoded_payload, PAYLOAD);

    assert_eq!(decoded_header, Header::<()> {
        alg: Some(Signing::Es256),
        ..Default::default()
    });
}