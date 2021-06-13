use actix_web::{get, middleware::Logger, post, web, App, HttpResponse, HttpServer, Responder};
use log::{debug, error, info, log_enabled, Level};
use serde::{Deserialize, Serialize};

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
struct AuthToken {
    username: String,
    flags: Vec<String>,
    iat: u64,
    uid: String,
    group: Option<String>,
    nonce: String,
}

#[derive(Serialize)]
struct AuthResponse {
    status: AuthStatus,
}

#[post("/")]
async fn authenticate(info: web::Json<AuthRequest>) -> impl Responder {
    HttpResponse::Ok()
}

#[get("/status")]
async fn healthcheck() -> impl Responder {
    HttpResponse::Ok()
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();
    HttpServer::new(|| {
        App::new()
            .wrap(Logger::default())
            .service(authenticate)
            .service(healthcheck)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
