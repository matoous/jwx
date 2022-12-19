use std::marker::PhantomData;

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    err,
    error::{Error, Type},
    jwk,
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    alg: String,
    typ: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    enc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

/// JSON Web Tokens as described in [RFC7519](https://tools.ietf.org/html/rfc7519).
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt<T> {
    pub header: Option<Header>,
    pub payload: T,
    pub signature: Option<String>,
}

struct Parser<'a, T: DeserializeOwned + Serialize> {
    token: &'a str,
    verification_key: Option<&'a jwk::Jwk>,

    phantom: PhantomData<&'a T>,
}

impl<'a, T: DeserializeOwned + Serialize> Parser<'a, T> {
    fn new(token: &'a str) -> Self {
        Self {
            token,
            verification_key: None,
            phantom: PhantomData,
        }
    }

    fn with_verification_key(mut self, verifier: &'a jwk::Jwk) -> Self {
        self.verification_key = Some(verifier);
        self
    }

    fn parse(self) -> Result<Jwt<T>, Error> {
        let raw_segments: Vec<&str> = self.token.split(".").collect();
        if raw_segments.len() != 3 {
            return Err(err!(Invalid, "JWT does not have 3 segments"));
        }

        let header_segment = raw_segments[0];
        let payload_segment = raw_segments[1];
        let signature = raw_segments[2].to_string();

        let header = decode_segment::<Header>(header_segment)
            .or(Err(err!(Invalid, "Failed to decode header")))?;
        let payload = decode_segment::<T>(payload_segment)
            .or(Err(err!(Invalid, "Failed to decode payload")))?;

        Ok(Jwt {
            header: Some(header),
            payload,
            signature: Some(signature),
        })
    }
}

impl<T: DeserializeOwned + Serialize> Jwt<T> {
    fn new(payload: T) -> Jwt<T> {
        Jwt {
            header: None,
            payload,
            signature: None,
        }
    }

    fn from<'a>(token: &'a str) -> Parser<'a, T> {
        Parser::new(token)
    }

    fn sign(&self, jwk: &jwk::Jwk) -> Result<String, Error> {
        let mut token = encode_segment(&Header {
            alg: jwk.alg(),
            typ: "JWT".into(),
            kid: jwk.kid.clone(),
            enc: None,
            cty: None,
        })?;
        token.push('.');
        token.push_str(&encode_segment(&self.payload)?);

        let signature = jwk.sign(token.as_bytes())?;
        let payload_segment = Base64UrlUnpadded::encode_string(&signature);

        token.push('.');
        token.push_str(&payload_segment);

        Ok(token)
    }
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = Base64UrlUnpadded::decode_vec(segment)
        .or(Err(err!(Invalid, "Failed to decode segment")))?;

    let slice = String::from_utf8_lossy(&raw);
    let decoded: T =
        serde_json::from_str(&slice).or(Err(err!(Invalid, "Failed to decode segment")))?;

    Ok(decoded)
}

#[inline]
fn encode_segment<T: Serialize>(segment: &T) -> Result<String, Error> {
    let encoded = serde_json::to_vec(segment).or(Err(err!(Invalid, "Failed to decode segment")))?;
    Ok(Base64UrlUnpadded::encode_string(&encoded))
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
        let jwt: Jwt<Claims> = Jwt::from("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").parse().unwrap();
        assert_eq!(
            jwt.header.unwrap(),
            Header {
                alg: "HS256".into(),
                typ: "JWT".into(),
                enc: None,
                kid: None,
                cty: None,
            }
        );
        assert_eq!(
            jwt.payload,
            Claims {
                sub: "1234567890".into(),
                name: "John Doe".into(),
                iat: 1516239022
            }
        );
        assert_eq!(
            jwt.signature.unwrap(),
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        );
    }

    #[test]
    fn sign() {
        let jwk = jwk::Jwk::parse(include_str!("./rs256_2048_private_key.json")).unwrap();
        let jwt = Jwt::new(Claims {
            sub: "1234567890".into(),
            name: "John Doe".into(),
            iat: 1516239022,
        });
        let res = jwt.sign(&jwk);
        assert!(res.is_ok());
        println!("{:?}", res);

        let jwt: Jwt<Claims> = Jwt::from(&res.unwrap())
            .with_verification_key(&jwk)
            .parse()
            .unwrap();
        assert_eq!(
            jwt.header.unwrap(),
            Header {
                alg: "RS256".into(),
                typ: "JWT".into(),
                kid: Some("test".into()),
                enc: None,
                cty: None,
            }
        );
        assert_eq!(
            jwt.payload,
            Claims {
                sub: "1234567890".into(),
                name: "John Doe".into(),
                iat: 1516239022
            }
        );
        assert_eq!(
            jwt.signature.unwrap(),
            "ATamiUP7uF_FWIemhEv610lFOZlyhCktRET9QiEQUuBKmL-V7O9G52I9x7J_W-oq2e_nTQHDEXNQjsXUTf9wBfku8maWkcfULRtD47ToyHG4mowThtuhTtJgwF9oQQlOAndn6zLllIf_tbL-rqWv36KdoskhBJn-RPYV495ZVkY8vNl9cf9mFLA5z2tvTVc8uJapLPP-t-l_EQwAWHGKRjFHKoeejt-_UsaXyRXrR7M_MtCz8QBgCeC4E9JeoBPfKS43ZJHhqW6TOb786gaR6H6-0iEz3SF0pHs7Fm8Qrus5yqSe4zpWbHafG2j00e4t2HSP4Eg664iy5cNREB2sGw"
        );
    }

    #[test]
    fn verify() {
        let key = jwk::Jwk::parse(include_str!("rs256_2048_private_key.json")).unwrap();
        let jwt: Jwt<Claims> = Jwt::from("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.YCSbIl71ucUlggqB4_6dErtfMq3n80LLKCbguSKp3iN8TZ_iRBW3Dw-75MlC8ooCFw7ketVxbPhkfvbGsyZkIfM1LIg4iY7mlxtFkxZUrY5mT7ymJRNJDLXAOvHpYnOckjgmjOQcGbin_LECxkqywi7BrOemEYZl5hPEJ3Wsgk-Ca4LNqk2XXaHpT-Tiz4Qqc6UDagn83bZDQrHSedq-67HoWiOQNLipaG_7si4yRNOZKry3YFkulrE7K64sT92z_uEg4WOcZXtXtwhnrNdcnlw0eWle97N_L7pxYF1DUraZvnxuiiYcqNfbub29op0-ZskCNhwM_1OLbC8axTdpTQ").with_verification_key(&key).parse().unwrap();
    }
}
