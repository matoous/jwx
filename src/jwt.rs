use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::{
    err,
    error::{Error, Type},
};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    alg: String,
    typ: String,
    enc: Option<String>,
}

/// JSON Web Tokens as described in [RFC7519](https://tools.ietf.org/html/rfc7519).
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwt<T> {
    pub header: Header,
    pub payload: T,
    pub signature: String,
}

impl<T: DeserializeOwned> Jwt<T> {
    fn decode(token: &str) -> Result<Self, Error> {
        let raw_segments: Vec<&str> = token.split(".").collect();
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
            header,
            payload,
            signature,
        })
    }
}

fn decode_segment<T: DeserializeOwned>(segment: &str) -> Result<T, Error> {
    let raw = base64::decode_engine(
        segment,
        &base64::engine::fast_portable::FastPortable::from(
            &base64::alphabet::URL_SAFE,
            base64::engine::fast_portable::NO_PAD,
        ),
    )
    .or(Err(err!(Invalid, "Failed to decode segment")))?;
    let slice = String::from_utf8_lossy(&raw);
    let decoded: T =
        serde_json::from_str(&slice).or(Err(err!(Invalid, "Failed to decode segment")))?;

    Ok(decoded)
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
        let jwt: Jwt<Claims> = Jwt::decode("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c").unwrap();
        assert_eq!(
            jwt.header,
            Header {
                alg: "HS256".into(),
                typ: "JWT".into(),
                enc: None,
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
        assert_eq!(jwt.signature, "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c");
    }
}
