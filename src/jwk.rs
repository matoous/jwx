use base64ct::{Base64UrlUnpadded, Encoding};
use rsa::{BigUint, PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};

use crate::{
    err,
    error::{Error, Type},
};

pub trait Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error>;
}

pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error>;
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RsaPublic {
    #[serde(default)]
    pub e: String,
    #[serde(default)]
    pub n: String,
}

impl Verifier for RsaPublic {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let pkc = RsaPublicKey::new(
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.n.as_str()).unwrap()),
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.e.as_str()).unwrap()),
        )
        .unwrap();
        pkc.verify(PaddingScheme::new_pkcs1v15_sign_raw(), message, signature)
            .or(Err(err!(
                Certificate,
                "Signature does not match certificate"
            )))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct RsaPrivate {
    #[serde(default)]
    pub e: String,
    #[serde(default)]
    pub n: String,
    #[serde(default)]
    pub p: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub d: String,

    pub qi: Option<String>,
    pub dp: Option<String>,
    pub dq: Option<String>,
}

impl Verifier for RsaPrivate {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        let pkc = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.n.as_str()).unwrap()),
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.e.as_str()).unwrap()),
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.d.as_str()).unwrap()),
            vec![
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.p.as_str()).unwrap()),
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.q.as_str()).unwrap()),
            ],
        )
        .unwrap();
        pkc.verify(PaddingScheme::new_pkcs1v15_sign_raw(), message, signature)
            .or(Err(err!(
                Certificate,
                "Signature does not match certificate"
            )))
    }
}

impl Signer for RsaPrivate {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let pkc = RsaPrivateKey::from_components(
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.n.as_str()).unwrap()),
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.e.as_str()).unwrap()),
            BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.d.as_str()).unwrap()),
            vec![
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.p.as_str()).unwrap()),
                BigUint::from_bytes_be(&Base64UrlUnpadded::decode_vec(self.q.as_str()).unwrap()),
            ],
        )
        .unwrap();
        pkc.sign(PaddingScheme::new_pkcs1v15_sign_raw(), message)
            .map_err(|_| err!(Internal, "Sign message"))
    }
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum Key {
    RSAPrivate(RsaPrivate),
    RSAPublic(RsaPublic),
}

impl Verifier for Key {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        match self {
            Key::RSAPrivate(key) => key.verify(message, signature),
            Key::RSAPublic(key) => key.verify(message, signature),
        }
    }
}

impl Signer for Key {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Key::RSAPrivate(key) => key.sign(message),
            _ => Err(err!(Invalid, "Key doesn't support signing")),
        }
    }
}

/// JSON Web Key as described in [RFC7517](https://www.rfc-editor.org/rfc/rfc7517).
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Jwk {
    pub kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#s256")]
    pub x5t_s256: Option<String>,

    #[serde(flatten)]
    key: Key,
}

impl Jwk {
    /// Returns the alg of this [`Jwk`].
    pub fn alg(&self) -> String {
        match self.key {
            Key::RSAPrivate(_) => "RS256".into(),
            Key::RSAPublic(_) => "RS256".into(),
        }
    }

    pub fn parse(key: &str) -> Result<Self, Error> {
        let jwk: Jwk =
            serde_json::from_str(key).or(Err(err!(Invalid, "Failed to decode segment")))?;
        Ok(jwk)
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), Error> {
        self.key.verify(message, signature)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        self.key.sign(message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Claims {
        sub: String,
        name: String,
        iat: i64,
    }

    #[test]
    fn decode() {
        let jwk = Jwk::parse(include_str!("rs256_2048_private_key.json")).unwrap();

        let want_jwk = Jwk {
            kty: "RSA".into(),
            alg: Some("RS256".into()),
            kid: Some("test".into()),
            key_ops: None,
            x5u: None,
            x5c: None,
            x5t: None,
            x5t_s256: None,
            key: Key::RSAPrivate(RsaPrivate {
                p: "z0efhRpEUlBIlQyT2xhYrXhZHIDZs2oxOM1MpRcwdOPW1qo4fG7JrbIQ2kQepLY6zK-SssBw4KdcUhG_OuDcx-uIr6LUf0VHp0Af1ieyiceXexuBQw8URzyVCg9e8kFICHshyz6dVqS5Y1OM8kIS5l1WkYlSx7NFU0K-jo-CSK0".into(),
                q: "uW0XqavXEr2uCpMF1Nh9SgjkaRbLhCd8x_RZpTRDpf0BqUaUNbrtF1udK6weuVh6xgLKUoE1SdjUHs5AvQmVd14aKDeYu19AQJgfnn4Y6hB2zkwYp5jCuV1PJKteC-p7XJERO8ABQNURe-PRBpfHKb4Ohp7qvW0oeQ0DZfF6K7E".into(),
                d: "hCDlcedDhDWv9tvGBOmRPLCL7zJMckfn0f93-ZCTa5sY-FHz4Ot62Y_SLxOJjrnaGRcJqAqZqvJVXSwRzn-Vvvvgnpp3ZYCebiiyGOfV7_1E5Mdo6fNmZ1vAWfGfTghL85Td3VnryU0W1eo0gWvEx2vcSnam7I6tLmPTv4fg_7x8Uw5DeIXiq-qd8sJmBOmOXaymdRTGHxC5U-KfxXbz61-i0F099SvvSBOhY6joGlBqoxHnGlq94bjcCOwSG-cKf1gJu7mWr6EJZYHqI271S-Xn_PolHH0QzFNszQm9fMD0eQF7tJv6gchPupa2Wd5nsLsHV11hfbxc6sVmV3oLAQ".into(),
                qi: Some( "F1QMnwPd4nEKPQdwMIVs9dmD03FPQKaC2yUx_SD2BN5hLNmMy89jwa7BcwDum5ZyN22wT6JOEc7FC-tA3-0j88VvIyihdgjFJWtpUpbvUq_1ehVwh3gc17YJm27xBYKwlFmpQLVWG4wg1h52mXlZR_9L6cNf6H4CTDFft26RxUc".into()),
                dp: Some("CAO28UiQt7YO-GRiGyiX1S1AFNAOmtdSS-X0PrXk08AzgF1Yjcci2Sp3aFkV7jx1jZCEVZEHTEhsU2gIQtiK8Nf0kwXyvXEKUjcyg-9JAfbLrqDjoJomqJJ5GMh7XVaU2G8aYWdsYftAh8ylOIDBhlK5lCsBHmOaHJwKDi0SVok".into()),
                dq: Some( "hrl15OifBtXcW4CBTynQtncJhjVyv111c07dx4PW1waiK1zFmNhtJXiCFNYlKKPZ6H7kg9evYS1yycMwFGmfOLCdrrTeet11MLmW17Bk58P4nmF51GPQr5_VPh5o4Z2H7jTU4aXbA0EMSAi5ueGTaofVxAg5JFLogjNrUamHC7E".into()),
                e: "AQAB".into(),
                n: "liMW7uxnzq8KejzQA1YC-Zk9lrV3NI3wB49pIMtzlOYwDvZOl_BbfigSCJU-8wBONAZ5is3-Ww_kOuE6KCqhGL0wSPvs5Wv7TrN_ZQNZtkM9WbJC3nIXTlLycXWFh2kh3_B0H5D4Jiz9eXZO2G1AljRkTf18K6Ep-dyJSqM8YYBxQBlE2tmhCWf-S7Zq0exwzJXeOtJ8tCvY-L25dIOBEJ7lh_FQ05iSVE1AL_PYeGKuo8oYXHvt8VUFznD4d1B9NSipmiKZuQAbbrH4Oyq-TPb0_twq2WtvN4iBCmnOosgRzmMpm2yuJ-d2kTcF8ELbJFZgVtlD1wpnO3BumrtOnQ".into(),
            }),
        };
        assert_eq!(jwk, want_jwk);
    }

    #[test]
    fn rsa() {
        let key = Jwk::parse(include_str!("rs256_2048_private_key.json")).unwrap();

        let message = "1234567890";
        let signature = key.sign(message.as_bytes());
        assert!(signature.is_ok());
        let verify = key.verify(message.as_bytes(), &signature.unwrap());
        assert!(verify.is_ok());
    }
}
