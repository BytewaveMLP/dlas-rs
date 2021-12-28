extern crate ring;

#[macro_use]
extern crate rocket;

use derivative::Derivative;

use rocket::{
    serde::{json::Json, Deserialize},
    State,
};

use ldap3::{Ldap, LdapConnAsync};
use log::{debug, error, info, log_enabled, warn, Level};
use serde::Serialize;
use std::sync::Arc;

use dlas_rs::AuthTokenPayload;

#[derive(Deserialize, Derivative)]
#[derivative(Debug)]
struct AuthRequest {
    username: String,
    #[derivative(Debug = "ignore")]
    password: Option<String>,
    nonce: Option<String>,
    group: Option<String>,
    avatar: Option<bool>,
}

#[derive(Serialize, Debug)]
#[serde(rename_all = "lowercase")]
enum AuthStatus {
    Auth,
    Guest,
    BadPass,
    OutGroup,
    Banned,
}

struct KeypairState {
    keypair: Arc<ring::signature::Ed25519KeyPair>,
}

#[derive(Serialize, Derivative)]
#[derivative(Debug)]
struct AuthResponse {
    status: AuthStatus,
    #[derivative(Debug = "ignore")]
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ingroup: Option<String>,
}

#[post("/", data = "<auth_request>")]
async fn authenticate(
    auth_request: Json<AuthRequest>,
    keypair: &State<KeypairState>,
) -> Json<AuthResponse> {
    let auth_request = auth_request.into_inner();

    debug!("{:?}", auth_request);

    let (conn, mut ldap) = LdapConnAsync::new("ldap://localhost:389").await.unwrap();
    ldap3::drive!(conn);

    info!("Connected to LDAP server");

    let payload = AuthTokenPayload::new(
        auth_request.username.clone(),
        None,
        Some(auth_request.username),
        auth_request.group,
        auth_request.nonce,
    );

    debug!("{:?}", payload);

    let auth_response = AuthResponse {
        status: AuthStatus::Auth,
        token: Some(payload.sign(keypair.keypair.clone())),
        ingroup: None,
    };

    debug!("{:?}", auth_response);

    ldap.unbind().await.unwrap();

    info!("Disconnected from LDAP server");

    Json(auth_response)
}

#[rocket::main]
async fn main() {
    env_logger::init();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair =
        Arc::new(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap());

    rocket::build()
        .mount("/", routes![authenticate])
        .manage(KeypairState { keypair })
        .launch()
        .await
        .unwrap();
}
