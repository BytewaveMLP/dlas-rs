extern crate ring;

use serde::Serialize;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
pub struct AuthTokenPayload {
    username: String,
    flags: Option<Vec<String>>,
    iat: u64,
    uid: Option<String>,
    group: Option<String>,
    nonce: String,
}

impl AuthTokenPayload {
    pub fn new(
        username: String,
        flags: Option<Vec<String>>,
        uid: Option<String>,
        group: Option<String>,
        nonce: String,
    ) -> Self {
        AuthTokenPayload {
            username,
            flags,
            iat: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            uid,
            group,
            nonce,
        }
    }

    fn encode(&self) -> String {
        base64::encode(serde_json::to_string(self).unwrap().as_bytes())
    }

    pub fn sign(&self, keypair: Arc<ring::signature::Ed25519KeyPair>) -> String {
        // tokens will have at least 3 elements: version, data, signature
        let mut token = Vec::with_capacity(3);
        token.push("1"); // default version

        let payload = self.encode();
        token.push(&payload);

        let signature = keypair.sign(token.join(".").as_bytes());
        let signature = base64::encode(signature);

        token.push(&signature);

        token.join(".")
    }
}
