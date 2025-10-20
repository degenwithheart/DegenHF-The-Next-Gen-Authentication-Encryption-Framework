mod auth;

use auth::{EccAuthHandler, EccAuthOptions, UserClaims};
use chrono::Duration;
use rocket::fairing::{Fairing, Info, Kind};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::response::status;
use rocket::{get, post, routes, serde::json::Json, Build, Rocket};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Request model for user registration
#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
}

/// Request model for user login
#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

/// Response model for authentication
#[derive(Serialize)]
struct AuthResponse {
    token: String,
    message: String,
}

/// Response model for user data
#[derive(Serialize)]
struct UserResponse {
    user_id: String,
    username: String,
    message: String,
}

/// Response model for user profile
#[derive(Serialize)]
struct ProfileResponse {
    user_id: String,
    username: String,
    profile: Profile,
}

/// User profile data
#[derive(Serialize)]
struct Profile {
    email: String,
    role: String,
    created: String,
}

/// Health check response
#[derive(Serialize)]
struct HealthResponse {
    status: String,
    service: String,
}

/// User claims from request guard
pub struct AuthenticatedUser(pub UserClaims);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for AuthenticatedUser {
    type Error = &'static str;

    async fn from_request(req: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let auth_handler = req.rocket().state::<Arc<EccAuthHandler>>();

        if auth_handler.is_none() {
            return request::Outcome::Error((Status::InternalServerError, "Auth handler not available"));
        }

        let auth_handler = auth_handler.unwrap();

        // Extract token from Authorization header
        let auth_header = req.headers().get_one("Authorization");
        if auth_header.is_none() {
            return request::Outcome::Error((Status::Unauthorized, "Authorization header required"));
        }

        let auth_header = auth_header.unwrap();
        if !auth_header.starts_with("Bearer ") {
            return request::Outcome::Error((Status::Unauthorized, "Invalid authorization header format"));
        }

        let token = &auth_header[7..]; // Remove "Bearer " prefix

        // Verify token
        match auth_handler.verify_token(token).await {
            Ok(claims) => request::Outcome::Success(AuthenticatedUser(claims)),
            Err(_) => request::Outcome::Error((Status::Unauthorized, "Invalid token")),
        }
    }
}

/// Register a new user
#[post("/register", data = "<request>")]
async fn register(
    request: Json<RegisterRequest>,
    auth_handler: &rocket::State<Arc<EccAuthHandler>>,
) -> Result<Json<serde_json::Value>, status::Custom<Json<serde_json::Value>>> {
    match auth_handler.register(&request.username, &request.password).await {
        Ok(user_id) => {
            let response = serde_json::json!({
                "user_id": user_id,
                "message": "User registered successfully"
            });
            Ok(Json(response))
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            Err(status::Custom(Status::BadRequest, Json(error)))
        }
    }
}

/// Authenticate user and return token
#[post("/login", data = "<request>")]
async fn login(
    request: Json<LoginRequest>,
    auth_handler: &rocket::State<Arc<EccAuthHandler>>,
) -> Result<Json<AuthResponse>, status::Custom<Json<serde_json::Value>>> {
    match auth_handler.authenticate(&request.username, &request.password).await {
        Ok(token) => {
            let response = AuthResponse {
                token,
                message: "Login successful".to_string(),
            };
            Ok(Json(response))
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            Err(status::Custom(Status::Unauthorized, Json(error)))
        }
    }
}

/// Verify JWT token (protected)
#[get("/verify")]
async fn verify(user: AuthenticatedUser) -> Json<UserResponse> {
    let response = UserResponse {
        user_id: user.0.user_id,
        username: user.0.username,
        message: "Token is valid".to_string(),
    };
    Json(response)
}

/// Get user profile (protected)
#[get("/profile")]
async fn profile(user: AuthenticatedUser) -> Json<ProfileResponse> {
    let response = ProfileResponse {
        user_id: user.0.user_id,
        username: user.0.username,
        profile: Profile {
            email: "user@example.com".to_string(), // Mock data
            role: "user".to_string(),
            created: "2024-01-01".to_string(),
        },
    };
    Json(response)
}

/// Health check
#[get("/health")]
fn health() -> Json<HealthResponse> {
    let response = HealthResponse {
        status: "healthy".to_string(),
        service: "DegenHF-Rocket".to_string(),
    };
    Json(response)
}

/// CORS fairing for development
pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info {
            name: "CORS",
            kind: Kind::Response,
        }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut rocket::response::Response<'r>) {
        res.adjoin_header(rocket::http::Header::new("Access-Control-Allow-Origin", "*"));
        res.adjoin_header(rocket::http::Header::new("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS"));
        res.adjoin_header(rocket::http::Header::new("Access-Control-Allow-Headers", "Content-Type, Authorization"));

        if req.method() == rocket::http::Method::Options {
            res.set_status(Status::NoContent);
        }
    }
}

#[launch]
fn rocket() -> _ {
    // Initialize ECC auth handler
    let options = EccAuthOptions {
        hash_iterations: 100000,
        token_expiry: Duration::hours(24),
        cache_size: 10000,
        cache_ttl: Duration::minutes(5),
    };

    let auth_handler = Arc::new(
        EccAuthHandler::new(Some(options))
            .expect("Failed to initialize auth handler")
    );

    rocket::build()
        .manage(auth_handler)
        .attach(Cors)
        .mount("/api/auth", routes![register, login, verify, profile])
        .mount("/", routes![health])
}