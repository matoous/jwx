use serde::{Deserialize, Serialize};

use crate::{error::Error, jwt::Jwt};

/// JSON Web Key as described in [RFC7517](https://www.rfc-editor.org/rfc/rfc7517).
#[derive(Debug, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(default)]
    pub e: String,
    pub kty: String,
    pub alg: Option<String>,
    #[serde(default)]
    pub n: String,
    pub kid: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
    url: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

impl Jwks {
    pub fn new(url: String) -> Self {
        Self {
            url,
            keys: Vec::new(),
        }
    }

    #[cfg(feature = "reqwest")]
    pub async fn refresh(&mut self) {
        let body: JwksResponse = reqwest::get(&self.url).await.unwrap().json().await.unwrap();
        self.keys = body.keys
    }

    pub fn decode<T>(&self, token: &str) -> Result<Jwt<T>, Error> {
        Ok(Jwt {
            header: todo!(),
            payload: todo!(),
            signature: todo!(),
        })
    }

    pub fn verify<T>(&self, token: &Jwt<T>) -> Result<(), Error> {
        Ok(())
    }
}
