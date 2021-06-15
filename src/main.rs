extern crate ring;

use actix_web::{
    dev::{AppService, HttpServiceFactory},
    get,
    middleware::Logger,
    post, web, App, HttpResponse, HttpServer, Responder,
};
use log::{debug, error, info, log_enabled, Level};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use dlas_rs::AuthTokenPayload;

#[derive(Deserialize)]
struct AuthRequest {
    username: String,
    password: Option<String>,
    nonce: Option<String>,
    group: String,
    avatar: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum AuthStatus {
    Auth,
    Guest,
    BadPass,
    OutGroup,
    Banned,
}

#[derive(Serialize)]
struct AuthResponse {
    status: AuthStatus,
}

struct AppState {
    keypair: Arc<ring::signature::Ed25519KeyPair>,
}

#[post("/")]
async fn authenticate(
    data: web::Data<AppState>,
    request: web::Json<AuthRequest>,
) -> impl Responder {
    let token = AuthTokenPayload::new(
        "Bytewave".to_string(),
        None,
        None,
        None,
        "foobar".to_string(),
    );
    HttpResponse::Ok().body(token.sign(data.get_ref().keypair.clone()))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let rng = ring::rand::SystemRandom::new();
    let pkcs8_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let keypair =
        Arc::new(ring::signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).unwrap());

    HttpServer::new(move || {
        App::new()
            .data(AppState {
                keypair: keypair.clone(),
            })
            .wrap(Logger::default())
            .service(authenticate)
            .service(web::resource("/status").to(|| HttpResponse::Ok()))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
