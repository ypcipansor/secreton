use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{Html, Response},
    Form,
};
use serde::Deserialize;
use std::sync::Arc;
use crate::auth::{SessionService, AuthError};

pub async fn index() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Brankas Security System</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <header class="hero">
            <h1>Brankas Security System</h1>
            <p>Enterprise-grade secret management and access control</p>
        </header>

        <section class="features">
            <div class="feature-grid">
                <div class="feature-card">
                    <h3>🔐 Secure Storage</h3>
                    <p>Banking-grade encryption for all your secrets</p>
                </div>
                <div class="feature-card">
                    <h3>👥 Access Control</h3>
                    <p>Fine-grained permissions and policy management</p>
                </div>
                <div class="feature-card">
                    <h3>📊 Audit Logging</h3>
                    <p>Complete audit trail for compliance</p>
                </div>
                <div class="feature-card">
                    <h3>🔄 High Availability</h3>
                    <p>Distributed architecture with automatic failover</p>
                </div>
            </div>
        </section>

        <div class="cta-section">
            <a href="/login" class="btn btn-primary">Login to Dashboard</a>
        </div>
    </div>
</body>
</html>"#;
    Html(html.to_string())
}

pub async fn login_page() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Login to Brankas</h2>
            <form action="/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <div class="links">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>"#;
    Html(html.to_string())
}

#[derive(Deserialize)]
pub struct LoginForm {
    username: String,
    password: String,
}

/// SECURE LOGIN IMPLEMENTATION
/// Uses Argon2id, constant-time comparison, rate limiting, and session management
pub async fn login(
    State(auth): State<Arc<SessionService>>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Html<String>, StatusCode> {
    // Extract IP address and user agent for security logging
    let ip_address = headers
        .get("x-forwarded-for")
        .or_else(|| headers.get("x-real-ip"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    
    // Attempt login with proper authentication
    match auth.login(&form.username, &form.password, ip_address, user_agent).await {
        Ok(_session) => {
            // Successful login - redirect to dashboard
            // In production, set secure HTTP-only session cookie here
            Ok(Html::from(dashboard().await.0))
        }
        Err(AuthError::InvalidCredentials) => {
            let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Login to Brankas</h2>
            <div class="error-message">Invalid username or password</div>
            <form action="/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <div class="links">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>"#;
            Ok(Html(html.to_string()))
        }
        Err(AuthError::AccountLocked) => {
            let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Login to Brankas</h2>
            <div class="error-message">Account is locked due to too many failed login attempts. Please try again later.</div>
            <form action="/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <div class="links">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>"#;
            Ok(Html(html.to_string()))
        }
        Err(AuthError::RateLimitExceeded) => {
            let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Login to Brankas</h2>
            <div class="error-message">Too many login attempts. Please try again in 15 minutes.</div>
            <form action="/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <div class="links">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>"#;
            Ok(Html(html.to_string()))
        }
        Err(e) => {
            let error_msg = format!("Authentication error: {}", e);
            let html = format!(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="container">
        <div class="login-form">
            <h2>Login to Brankas</h2>
            <div class="error-message">{}</div>
            <form action="/login" method="post">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <button type="submit" class="btn btn-primary">Login</button>
            </form>
            <div class="links">
                <a href="/">← Back to Home</a>
            </div>
        </div>
    </div>
</body>
</html>"#, error_msg);
            Ok(Html(html))
        }
    }
}

pub async fn dashboard() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="dashboard">
        <nav class="sidebar">
            <h2>Brankas</h2>
            <ul>
                <li><a href="/dashboard" class="active">Dashboard</a></li>
                <li><a href="/secrets">Secrets</a></li>
                <li><a href="/policies">Policies</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <header class="page-header">
                <h1>Welcome, Current User</h1>
            </header>

            <div class="dashboard-grid">
                <div class="status-card">
                    <h3>System Status</h3>
                    <div class="status-indicator status-healthy">✓ All Systems Operational</div>
                </div>

                <div class="status-card">
                    <h3>Active Secrets</h3>
                    <div class="metric">1,234</div>
                </div>

                <div class="status-card">
                    <h3>Active Policies</h3>
                    <div class="metric">56</div>
                </div>

                <div class="status-card">
                    <h3>Recent Activity</h3>
                    <ul class="activity-list">
                        <li>Secret 'api-keys' accessed</li>
                        <li>Policy 'admin-access' updated</li>
                        <li>New user authenticated</li>
                    </ul>
                </div>
            </div>
        </main>
    </div>
</body>
</html>"#;
    Html(html.to_string())
}

pub async fn secrets_page() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secrets - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="dashboard">
        <nav class="sidebar">
            <h2>Brankas</h2>
            <ul>
                <li><a href="/dashboard">Dashboard</a></li>
                <li><a href="/secrets" class="active">Secrets</a></li>
                <li><a href="/policies">Policies</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <header class="page-header">
                <h1>Secret Management</h1>
                <button class="btn btn-primary">+ New Secret</button>
            </header>

            <div class="content-section">
                <div class="empty-state">
                    <h3>No secrets found</h3>
                    <p>Get started by creating your first secret.</p>
                    <button class="btn btn-primary">Create Secret</button>
                </div>
            </div>
        </main>
    </div>
</body>
</html>"#;
    Html(html.to_string())
}

pub async fn policies_page() -> Html<String> {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Policies - Brankas</title>
    <link rel="stylesheet" href="/static/css/style.css">
</head>
<body>
    <div class="dashboard">
        <nav class="sidebar">
            <h2>Brankas</h2>
            <ul>
                <li><a href="/dashboard">Dashboard</a></li>
                <li><a href="/secrets">Secrets</a></li>
                <li><a href="/policies" class="active">Policies</a></li>
                <li><a href="/logout">Logout</a></li>
            </ul>
        </nav>

        <main class="main-content">
            <header class="page-header">
                <h1>Access Policies</h1>
                <button class="btn btn-primary">+ New Policy</button>
            </header>

            <div class="content-section">
                <div class="empty-state">
                    <h3>No policies found</h3>
                    <p>Create access policies to control secret permissions.</p>
                    <button class="btn btn-primary">Create Policy</button>
                </div>
            </div>
        </main>
    </div>
</body>
</html>"#;
    Html(html.to_string())
}

pub async fn serve_static(Path(file): Path<String>) -> Result<Response<Vec<u8>>, StatusCode> {
    use crate::assets::Assets;

    let file = file.trim_start_matches('/');
    if let Some(content) = Assets::get(file) {
        let mime_type = mime_guess::from_path(file).first_or_octet_stream();
        
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("content-type", mime_type.as_ref())
            .body(content.data.to_vec())
            .unwrap())
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}
