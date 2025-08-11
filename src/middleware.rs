// Custom logging middleware for the auth service
//
// This middleware logs detailed information about all incoming requests and outgoing responses:
// - Request: Method, URI, remote address, authorization status
// - Response: Status code, request duration with color-coded emojis
// - Errors: Any errors that occur during request processing
//
// Usage in main.rs:
//   .with(LoggingMiddleware)
//
// Alternative built-in option:
//   .with(poem::middleware::Tracing)

use poem::{
    middleware::Middleware,
    Endpoint, IntoResponse, Request, Response, Result,
};
use std::time::Instant;
use tracing::{info, warn};

/// Custom logging middleware that logs request and response details
pub struct LoggingMiddleware;

impl<E: Endpoint> Middleware<E> for LoggingMiddleware {
    type Output = LoggingEndpoint<E>;

    fn transform(&self, ep: E) -> Self::Output {
        LoggingEndpoint { inner: ep }
    }
}

pub struct LoggingEndpoint<E> {
    inner: E,
}

impl<E: Endpoint> Endpoint for LoggingEndpoint<E> {
    type Output = Response;

    async fn call(&self, req: Request) -> Result<Self::Output> {
        let start_time = Instant::now();
        let method = req.method().to_string();
        let uri = req.uri().to_string();
        let remote_addr = req
            .remote_addr()
            .0
            .to_string();

        // Log authorization info (but not the actual token for security)
        let has_auth = req
            .headers()
            .get("authorization")
            .map(|_| "Bearer token present")
            .unwrap_or("No authorization");

        // Log request details
        info!(
            "🚀 Request: {} {} from {} | Auth: {}",
            method, uri, remote_addr, has_auth
        );

        // Call the inner endpoint and convert to Response
        let result = self.inner.call(req).await;

        let duration = start_time.elapsed();

        match result {
            Ok(response) => {
                let response = response.into_response();
                let status = response.status();
                let duration_ms = duration.as_millis();

                if status.is_success() {
                    info!(
                        "✅ Response: {} {} | Status: {} | Duration: {}ms",
                        method, uri, status, duration_ms
                    );
                } else if status.is_client_error() {
                    warn!(
                        "⚠️  Response: {} {} | Status: {} | Duration: {}ms",
                        method, uri, status, duration_ms
                    );
                } else if status.is_server_error() {
                    warn!(
                        "❌ Response: {} {} | Status: {} | Duration: {}ms",
                        method, uri, status, duration_ms
                    );
                } else {
                    info!(
                        "📝 Response: {} {} | Status: {} | Duration: {}ms",
                        method, uri, status, duration_ms
                    );
                }

                Ok(response)
            }
            Err(err) => {
                let duration_ms = duration.as_millis();
                warn!(
                    "❌ Error: {} {} | Error: {} | Duration: {}ms",
                    method, uri, err, duration_ms
                );
                Err(err)
            }
        }
    }
}
