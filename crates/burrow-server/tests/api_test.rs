//! Integration tests for Burrow Server API

use axum::{
    body::Body,
    http::{header, Method, Request, StatusCode},
};
use serde_json::{json, Value};
use tower::ServiceExt;

mod common;
use common::*;

#[tokio::test]
async fn test_health_check() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body(response).await;
    assert_eq!(body["status"], "ok");
    assert_eq!(body["service"], "burrow-server");
}

#[tokio::test]
async fn test_user_registration() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "test@example.com",
                        "password": "password123",
                        "name": "Test User"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body(response).await;
    assert!(body["token"].is_string());
    assert_eq!(body["user"]["email"], "test@example.com");
    assert_eq!(body["user"]["role"], "admin"); // First user is admin
}

#[tokio::test]
async fn test_user_login() {
    let app = create_test_app().await;

    // Register first
    let _ = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "test@example.com",
                        "password": "password123",
                        "name": "Test User"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    // Login
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "test@example.com",
                        "password": "password123"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body(response).await;
    assert!(body["token"].is_string());
}

#[tokio::test]
async fn test_create_network_requires_auth() {
    let app = create_test_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/networks")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(json!({"name": "Test Network"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_create_network_with_auth() {
    let app = create_test_app().await;

    // Register and get token
    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "test@example.com",
                        "password": "password123",
                        "name": "Test User"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let register_body = response_body(register_response).await;
    let token = register_body["token"].as_str().unwrap();

    // Create network with auth
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/networks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(json!({"name": "Test Network"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body(response).await;
    assert_eq!(body["name"], "Test Network");
    assert!(body["id"].is_string());
    assert!(body["cidr"].is_string());
}

#[tokio::test]
async fn test_node_registration() {
    let app = create_test_app().await;

    // Register user
    let register_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/auth/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "email": "test@example.com",
                        "password": "password123",
                        "name": "Test User"
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    let token = response_body(register_response).await["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Create network
    let network_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/networks")
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::from(json!({"name": "Test Network"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    let network_id = response_body(network_response).await["id"]
        .as_str()
        .unwrap()
        .to_string();

    // Create invite
    let invite_response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri(format!("/api/networks/{}/invite", network_id))
                .header(header::AUTHORIZATION, format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    let invite_code = response_body(invite_response).await["code"]
        .as_str()
        .unwrap()
        .to_string();

    // Register node
    let response = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/api/register")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "invite_code": invite_code,
                        "name": "Test Node",
                        "public_key": "YBKaGeYm2c8cJTEhSqWHXaEQEEGh5kF8JZvYL3MWOVU=" // Valid base64, 44 chars
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = response_body(response).await;
    assert_eq!(body["node"]["name"], "Test Node");
    assert!(body["mesh_ip"].is_string());
}
