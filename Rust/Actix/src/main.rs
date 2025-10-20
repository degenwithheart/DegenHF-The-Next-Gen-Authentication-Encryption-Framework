mod auth;

use actix_web::{web, App, HttpServer, HttpResponse, Result as ActixResult, middleware::Logger};
use actix_web_httpauth::middleware::HttpAuthentication;
use actix_web_httpauth::extractors::bearer::{BearerAuth, Config as BearerConfig};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use auth::{EccAuthHandler, EccAuthOptions, UserClaims};
use chrono::Duration;

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

/// Validator function for Bearer authentication
async fn bearer_validator(
    req: actix_web::dev::ServiceRequest,
    credentials: BearerAuth,
) -> Result<actix_web::dev::ServiceRequest, (actix_web::Error, actix_web::dev::ServiceRequest)> {
    let auth_handler = req.app_data::<web::Data<Arc<EccAuthHandler>>>().cloned();

    if let Some(auth_handler) = auth_handler {
        match auth_handler.verify_token(credentials.token()).await {
            Ok(claims) => {
                // Store user claims in request extensions
                req.extensions_mut().insert(claims);
                Ok(req)
            }
            Err(_) => {
                let config = req.app_data::<BearerConfig>()
                    .map(|data| data.clone())
                    .unwrap_or_else(BearerConfig::default);
                Err((actix_web_httpauth::extractors::AuthenticationError::from(config).into(), req))
            }
        }
    } else {
        let config = req.app_data::<BearerConfig>()
            .map(|data| data.clone())
            .unwrap_or_else(BearerConfig::default);
        Err((actix_web_httpauth::extractors::AuthenticationError::from(config).into(), req))
    }
}

/// Register a new user
async fn register(
    request: web::Json<RegisterRequest>,
    auth_handler: web::Data<Arc<EccAuthHandler>>,
) -> ActixResult<HttpResponse> {
    match auth_handler.register(&request.username, &request.password).await {
        Ok(user_id) => {
            let response = serde_json::json!({
                "user_id": user_id,
                "message": "User registered successfully"
            });
            Ok(HttpResponse::Created().json(response))
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            Ok(HttpResponse::BadRequest().json(error))
        }
    }
}

/// Authenticate user and return token
async fn login(
    request: web::Json<LoginRequest>,
    auth_handler: web::Data<Arc<EccAuthHandler>>,
) -> ActixResult<HttpResponse> {
    match auth_handler.authenticate(&request.username, &request.password).await {
        Ok(token) => {
            let response = AuthResponse {
                token,
                message: "Login successful".to_string(),
            };
            Ok(HttpResponse::Ok().json(response))
        }
        Err(e) => {
            let error = serde_json::json!({ "error": e.to_string() });
            Ok(HttpResponse::Unauthorized().json(error))
        }
    }
}

/// Verify JWT token (protected)
async fn verify(user: web::ReqData<UserClaims>) -> ActixResult<HttpResponse> {
    let response = UserResponse {
        user_id: user.user_id.clone(),
        username: user.username.clone(),
        message: "Token is valid".to_string(),
    };
    Ok(HttpResponse::Ok().json(response))
}

/// Get user profile (protected)
async fn profile(user: web::ReqData<UserClaims>) -> ActixResult<HttpResponse> {
    let response = ProfileResponse {
        user_id: user.user_id.clone(),
        username: user.username.clone(),
        profile: Profile {
            email: "user@example.com".to_string(), // Mock data
            role: "user".to_string(),
            created: "2024-01-01".to_string(),
        },
    };
    Ok(HttpResponse::Ok().json(response))
}

/// Health check
async fn health() -> ActixResult<HttpResponse> {
    let response = HealthResponse {
        status: "healthy".to_string(),
        service: "DegenHF-Actix".to_string(),
    };
    Ok(HttpResponse::Ok().json(response))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

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

    println!("🚀 DegenHF-Actix server starting on http://localhost:8080");
    println!("📖 API Documentation:");
    println!("   POST /api/auth/register - Register new user");
    println!("   POST /api/auth/login    - Login user");
    println!("   GET  /api/auth/verify   - Verify token (protected)");
    println!("   GET  /api/auth/profile  - Get user profile (protected)");
    println!("   GET  /health            - Health check");

    HttpServer::new(move || {
        let auth = HttpAuthentication::bearer(bearer_validator);

        App::new()
            .app_data(web::Data::new(auth_handler.clone()))
            .wrap(Logger::default())
            .wrap(
                actix_web::middleware::Cors::default()
                    .allow_any_origin()
                    .allow_any_method()
                    .allow_any_header()
            )
            // Public routes
            .route("/api/auth/register", web::post().to(register))
            .route("/api/auth/login", web::post().to(login))
            .route("/health", web::get().to(health))
            // Protected routes
            .service(
                web::scope("/api/auth")
                    .wrap(auth)
                    .route("/verify", web::get().to(verify))
                    .route("/profile", web::get().to(profile))
            )
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}