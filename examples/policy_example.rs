//! Example of using the policy system in Brankas Adhyaksa

use axum::{
    extract::Extension,
    routing::get,
    Router,
    http::StatusCode,
    response::IntoResponse,
};
use brankas_adhyaksa::{
    policy::{
        Policy, Effect, Condition, Subject, Action, PolicyEngine,
        middleware::{policy_middleware, PolicyExt}
    },
    auth::Claims,
};
use std::{collections::HashMap, sync::Arc};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create a policy engine
    let mut policy_engine = PolicyEngine::new();
    
    // Define some policies
    let admin_policy = Policy {
        id: "admin-policy".to_string(),
        description: "Allow all actions for admin users".to_string(),
        effect: Effect::Allow,
        actions: vec!["*".to_string()],
        resources: vec!["*".to_string()],
        conditions: vec![
            Condition::StringEquals { 
                key: "role".to_string(), 
                value: "admin".to_string() 
            }
        ],
        priority: 100,
    };
    
    let read_secret_policy = Policy {
        id: "read-secret-policy".to_string(),
        description: "Allow reading non-admin secrets".to_string(),
        effect: Effect::Allow,
        actions: vec!["secrets:read".to_string()],
        resources: vec!["secrets:non-admin:*".to_string()],
        conditions: vec![],
        priority: 10,
    };
    
    // Add policies to the engine
    policy_engine.add_policy(admin_policy);
    policy_engine.add_policy(read_secret_policy);
    
    // Create the router
    let app = Router::new()
        .route("/secrets/:id", get(get_secret))
        .layer(Extension(Arc::new(policy_engine)));
    
    // Run the server
    let addr = "127.0.0.1:3000".parse().unwrap();
    println!("Server running on http://{}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    
    Ok(())
}

async fn get_secret(
    claims: Claims,
    Extension(policy_engine): Extension<Arc<PolicyEngine>>,
) -> impl IntoResponse {
    // Create a subject from the JWT claims
    let subject = Subject::new(claims.sub)
        .with_role(claims.role);
    
    // Create some context (e.g., from request parameters)
    let mut context = HashMap::new();
    context.insert("resource_owner".to_string(), "user123".to_string());
    
    // Check if the user is allowed to read this secret
    if !policy_engine.is_allowed(
        &subject,
        "secrets:read",
        "secrets:non-admin:user123",
        &context,
    ) {
        return (StatusCode::FORBIDDEN, "Access denied");
    }
    
    // User is authorized, return the secret
    (StatusCode::OK, "Super secret data!")
}
