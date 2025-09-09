use std::ops::{Deref, DerefMut};

use jsonwebtoken::{decode, Algorithm, Validation};
use poem::Request;
use poem_openapi::{SecurityScheme, auth::Bearer};
use serde::{Deserialize, Serialize};

use crate::config::CONFIG;

/// Structured permission with action, resource, and scope
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Permission {
    pub action: String,
    pub resource: String,
    pub scope: String,
}

impl Permission {
    pub fn new(action: &str, resource: &str, scope: &str) -> Self {
        Self {
            action: action.to_string(),
            resource: resource.to_string(),
            scope: scope.to_string(),
        }
    }

    /// Parse from "action:resource:scope" format
    pub fn from_string(permission_str: &str) -> Option<Self> {
        let parts: Vec<&str> = permission_str.split(':').collect();
        if parts.len() == 3 {
            Some(Self::new(parts[0], parts[1], parts[2]))
        } else {
            None
        }
    }

    /// Convert to "action:resource:scope" format
    pub fn to_string(&self) -> String {
        format!("{}:{}:{}", self.action, self.resource, self.scope)
    }
}

/// Our claims struct, it needs to derive `Serialize` and/or `Deserialize`
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Claims {
    pub sub: String,
    pub company: String,
    pub exp: usize,
    pub permissions: Vec<Permission>,
}

/// Minimal JWT claims containing only essential information
#[derive(Debug, Serialize, Deserialize)]
pub struct MinimalClaims {
    pub sub: String,        // User ID
    pub session_id: String, // Session identifier for Redis lookup
    pub exp: usize,         // Expiration timestamp
}

/// Session data stored in Redis
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SessionData {
    pub user_id: String,
    pub company: String,
    pub permissions: Vec<Permission>,
    pub created_at: i64,
    pub last_accessed: i64,
}

#[derive(SecurityScheme)]
#[oai(
    ty = "bearer",
    key_in = "header",
    key_name = "Bearer",
    checker = "key_checker"
)]
#[allow(dead_code)]
pub struct BearerAuthorization(pub Claims);

impl BearerAuthorization {
    /// Check if the user has a specific permission
    pub fn has_permission(&self, action: &str, resource: &str) -> bool {
        // Check for both "any" scope and "owned" scope permissions
        let any_permission = Permission::new(action, resource, "any");
        let owned_permission = Permission::new(action, resource, "owned");
        self.permissions.contains(&any_permission) || self.permissions.contains(&owned_permission)
    }

    /// Check if the user has a specific permission with a specific scope
    pub fn has_permission_with_scope(&self, action: &str, resource: &str, scope: &str) -> bool {
        let required_permission = Permission::new(action, resource, scope);
        self.permissions.contains(&required_permission)
    }

    /// Check if the user has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[(String, String)]) -> bool {
        permissions.iter().any(|(action, resource)| {
            self.has_permission(action, resource)
        })
    }

    /// Check if the user has any of the specified permissions with specific scopes
    pub fn has_any_permission_with_scope(&self, permissions: &[(String, String, String)]) -> bool {
        permissions.iter().any(|(action, resource, scope)| {
            self.has_permission_with_scope(action, resource, scope)
        })
    }
}

async fn key_checker(req: &Request, token: Bearer) -> Option<Claims> {
    let decoding_key = jsonwebtoken::DecodingKey::from_rsa_pem(CONFIG.jwt_public_key.as_bytes()).ok()?;
    let token_data = decode::<MinimalClaims>(
        &token.token,
        &decoding_key,
        &Validation::new(Algorithm::RS256),
    ).ok()?;
    
    // Get Redis client from request data
    let redis_client = req.data::<redis::Client>()?;
    let mut conn = redis_client.get_connection().ok()?;
    
    // Retrieve session data from Redis
    let session_key = format!("session:{}", token_data.claims.session_id);
    let session_json: String = redis::cmd("GET")
        .arg(&session_key)
        .query(&mut conn)
        .ok()?;
    
    let session_data: SessionData = serde_json::from_str(&session_json).ok()?;
    
    // Update last accessed time
    let mut updated_session = session_data.clone();
    updated_session.last_accessed = chrono::Utc::now().timestamp();
    let updated_json = serde_json::to_string(&updated_session).ok()?;
    let _: () = redis::cmd("SET")
        .arg(&session_key)
        .arg(&updated_json)
        .arg("EX")
        .arg(30 * 24 * 60 * 60) // 30 days expiration
        .query(&mut conn)
        .ok()?;
    
    // Convert to full Claims structure
    Some(Claims {
        sub: session_data.user_id,
        company: session_data.company,
        exp: token_data.claims.exp,
        permissions: session_data.permissions,
    })
}

impl Deref for BearerAuthorization {
    type Target = Claims;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BearerAuthorization {

    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}