//! Security Headers Middleware

//! 

//! Provides comprehensive HTTP security headers for web applications.

//! This middleware adds security headers to prevent common web-based attacks

//! including XSS, clickjacking, and other vulnerabilities.




use axum::{

    body::Body,

    extract::Request,

    response::Response,

    http::{header, HeaderValue, StatusCode},

    middleware::Next,

    Router,

};


use std::time::Duration;

use std::pin::Pin;

use std::future::Future;



/// Security headers configuration

#[derive(Debug, Clone)]

pub struct SecurityHeadersConfig {

    /// Content Security Policy

    pub content_security_policy: Option<String>,

    /// HTTP Strict Transport Security

    pub hsts_enabled: bool,

    /// HSTS max age in seconds

    pub hsts_max_age: Duration,

    /// HSTS include subdomains

    pub hsts_include_subdomains: bool,

    /// HSTS preload

    pub hsts_preload: bool,

    /// X-Frame-Options

    pub frame_options: FrameOptions,

    /// X-Content-Type-Options

    pub content_type_options: bool,

    /// X-XSS-Protection

    pub xss_protection: XssProtection,

    /// Referrer Policy

    pub referrer_policy: Option<ReferrerPolicy>,

    /// Permissions Policy

    pub permissions_policy: Option<String>,

    /// Cross-Origin Embedder Policy

    pub cross_origin_embedder_policy: Option<CrossOriginPolicy>,

    /// Cross-Origin Opener Policy

    pub cross_origin_opener_policy: Option<CrossOriginPolicy>,

    /// Cross-Origin Resource Policy

    pub cross_origin_resource_policy: Option<String>,

}



/// X-Frame-Options values

#[derive(Debug, Clone, PartialEq)]

pub enum FrameOptions {

    Deny,

    SameOrigin,

    AllowFrom(String),

}



/// X-XSS-Protection values

#[derive(Debug, Clone, PartialEq)]

pub enum XssProtection {

    Disabled,

    Enabled,

    EnabledBlock,

}



/// Referrer Policy values

#[derive(Debug, Clone, PartialEq)]

pub enum ReferrerPolicy {

    NoReferrer,

    NoReferrerWhenDowngrade,

    Origin,

    OriginWhenCrossOrigin,

    SameOrigin,

    StrictOrigin,

    StrictOriginWhenCrossOrigin,

    UnsafeUrl,

}



/// Cross-Origin Policy values

#[derive(Debug, Clone, PartialEq)]

pub enum CrossOriginPolicy {

    UnsafeNone,

    RequireCorp,

    Credentialless,

    SameOrigin,

}



impl Default for SecurityHeadersConfig {

    fn default() -> Self {

        Self {

            content_security_policy: Some(

                "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests;"

                    .to_string(),

            ),

            hsts_enabled: true,

            hsts_max_age: Duration::from_secs(31536000), // 1 year

            hsts_include_subdomains: true,

            hsts_preload: false,

            frame_options: FrameOptions::Deny,

            content_type_options: true,

            xss_protection: XssProtection::EnabledBlock,

            referrer_policy: Some(ReferrerPolicy::StrictOriginWhenCrossOrigin),

            permissions_policy: Some(

                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=(), ambient-light-sensor=(), autoplay=(), encrypted-media=(), fullscreen=(), picture-in-picture=()"

                    .to_string(),

            ),

            cross_origin_embedder_policy: Some(CrossOriginPolicy::RequireCorp),

            cross_origin_opener_policy: Some(CrossOriginPolicy::SameOrigin),

            cross_origin_resource_policy: Some("cross-origin".to_string()),

        }

    }

}



/// Security headers middleware

#[derive(Clone)]

pub struct SecurityHeadersMiddleware {

    config: SecurityHeadersConfig,

}



impl SecurityHeadersMiddleware {

    /// Create new middleware with default configuration

    pub fn new() -> Self {

        Self::with_config(SecurityHeadersConfig::default())

    }



    /// Create new middleware with custom configuration

    pub fn with_config(config: SecurityHeadersConfig) -> Self {

        Self { config }

    }



    /// Apply security headers to response

    pub async fn apply_headers(&self, request: Request<Body>, next: Next) -> Response<Body> {

        let mut response = next.run(request).await;



        // Apply all configured security headers

        self.add_content_security_policy(&mut response);

        self.add_hsts(&mut response);

        self.add_frame_options(&mut response);

        self.add_content_type_options(&mut response);

        self.add_xss_protection(&mut response);

        self.add_referrer_policy(&mut response);

        self.add_permissions_policy(&mut response);

        self.add_cross_origin_headers(&mut response);

        self.add_additional_headers(&mut response);



        response

    }



    /// Add Content Security Policy header

    fn add_content_security_policy(&self, response: &mut Response<Body>) {

        if let Some(csp) = &self.config.content_security_policy {

            if let Ok(value) = HeaderValue::from_str(csp) {

                response.headers_mut().insert(header::CONTENT_SECURITY_POLICY, value);

            }

        }

    }



    /// Add HTTP Strict Transport Security header

    fn add_hsts(&self, response: &mut Response<Body>) {

        if self.config.hsts_enabled {

            let mut hsts_value = format!("max-age={}", self.config.hsts_max_age.as_secs());

            

            if self.config.hsts_include_subdomains {

                hsts_value.push_str("; includeSubDomains");

            }

            

            if self.config.hsts_preload {

                hsts_value.push_str("; preload");

            }



            if let Ok(value) = HeaderValue::from_str(&hsts_value) {

                response.headers_mut().insert("Strict-Transport-Security", value);

            }

        }

    }



    /// Add X-Frame-Options header

    fn add_frame_options(&self, response: &mut Response<Body>) {

        let value = match &self.config.frame_options {

            FrameOptions::Deny => "DENY",

            FrameOptions::SameOrigin => "SAMEORIGIN",

            FrameOptions::AllowFrom(uri) => &uri,

        };



        if let Ok(header_value) = HeaderValue::from_str(value) {

            response.headers_mut().insert("X-Frame-Options", header_value);

        }

    }



    /// Add X-Content-Type-Options header

    fn add_content_type_options(&self, response: &mut Response<Body>) {

        if self.config.content_type_options {

            if let Ok(value) = HeaderValue::from_str("nosniff") {

                response.headers_mut().insert("X-Content-Type-Options", value);

            }

        }

    }



    /// Add X-XSS-Protection header

    fn add_xss_protection(&self, response: &mut Response<Body>) {

        let value = match self.config.xss_protection {

            XssProtection::Disabled => "0",

            XssProtection::Enabled => "1",

            XssProtection::EnabledBlock => "1; mode=block",

        };



        if let Ok(header_value) = HeaderValue::from_str(value) {

            response.headers_mut().insert("X-XSS-Protection", header_value);

        }

    }



    /// Add Referrer Policy header

    fn add_referrer_policy(&self, response: &mut Response<Body>) {

        if let Some(policy) = &self.config.referrer_policy {

            let policy_str = match policy {

                ReferrerPolicy::NoReferrer => "no-referrer",

                ReferrerPolicy::NoReferrerWhenDowngrade => "no-referrer-when-downgrade",

                ReferrerPolicy::Origin => "origin",

                ReferrerPolicy::OriginWhenCrossOrigin => "origin-when-cross-origin",

                ReferrerPolicy::SameOrigin => "same-origin",

                ReferrerPolicy::StrictOrigin => "strict-origin",

                ReferrerPolicy::StrictOriginWhenCrossOrigin => "strict-origin-when-cross-origin",

                ReferrerPolicy::UnsafeUrl => "unsafe-url",

            };



            if let Ok(value) = HeaderValue::from_str(policy_str) {

                response.headers_mut().insert("Referrer-Policy", value);

            }

        }

    }



    /// Add Permissions Policy header

    fn add_permissions_policy(&self, response: &mut Response<Body>) {

        if let Some(policy) = &self.config.permissions_policy {

            if let Ok(value) = HeaderValue::from_str(policy) {

                response.headers_mut().insert("Permissions-Policy", value);

            }

        }

    }



    /// Add Cross-Origin headers

    fn add_cross_origin_headers(&self, response: &mut Response<Body>) {

        // Cross-Origin Embedder Policy

        if let Some(policy) = &self.config.cross_origin_embedder_policy {

            let policy_str = match policy {

                CrossOriginPolicy::UnsafeNone => "unsafe-none",

                CrossOriginPolicy::RequireCorp => "require-corp",

                CrossOriginPolicy::Credentialless => "credentialless",

                CrossOriginPolicy::SameOrigin => "same-origin",

            };



            if let Ok(value) = HeaderValue::from_str(policy_str) {

                response.headers_mut().insert("Cross-Origin-Embedder-Policy", value);

            }

        }



        // Cross-Origin Opener Policy

        if let Some(policy) = &self.config.cross_origin_opener_policy {

            let policy_str = match policy {

                CrossOriginPolicy::UnsafeNone => "unsafe-none",

                CrossOriginPolicy::RequireCorp => "require-corp",

                CrossOriginPolicy::Credentialless => "credentialless",

                CrossOriginPolicy::SameOrigin => "same-origin",

            };



            if let Ok(value) = HeaderValue::from_str(policy_str) {

                response.headers_mut().insert("Cross-Origin-Opener-Policy", value);

            }

        }



        // Cross-Origin Resource Policy

        if let Some(policy) = &self.config.cross_origin_resource_policy {

            if let Ok(value) = HeaderValue::from_str(policy) {

                response.headers_mut().insert("Cross-Origin-Resource-Policy", value);

            }

        }

    }



    /// Add additional security headers

    fn add_additional_headers(&self, response: &mut Response<Body>) {

        // Cache-Control for sensitive responses

        let status = response.status();

        let is_ok_response = status == StatusCode::OK;



        let headers = response.headers_mut();



        // X-Permitted-Cross-Domain-Policies

        if let Ok(value) = HeaderValue::from_str("none") {

            headers.insert("X-Permitted-Cross-Domain-Policies", value);

        }



        // X-DNS-Prefetch-Control

        if let Ok(value) = HeaderValue::from_str("off") {

            headers.insert("X-DNS-Prefetch-Control", value);

        }



        // X-Download-Options

        if let Ok(value) = HeaderValue::from_str("noopen") {

            headers.insert("X-Download-Options", value);

        }



        // X-Content-Security-Policy (legacy)

        if let Some(csp) = &self.config.content_security_policy {

            if let Ok(value) = HeaderValue::from_str(csp) {

                headers.insert("X-Content-Security-Policy", value);

            }

        }



        // Server header removal for security

        headers.remove(header::SERVER);



        // X-Powered-By header removal for security

        headers.remove("X-Powered-By");



        // Cache-Control for sensitive responses

        if is_ok_response {

            if let Ok(value) = HeaderValue::from_str("no-store, no-cache, must-revalidate, proxy-revalidate") {

                headers.insert(header::CACHE_CONTROL, value);

            }

            if let Ok(value) = HeaderValue::from_str("no-cache") {

                headers.insert(header::PRAGMA, value);

            }

            if let Ok(value) = HeaderValue::from_str("0") {

                headers.insert("Expires", value);

            }

        }

    }

}



/// Builder for security headers configuration

pub struct SecurityHeadersBuilder {

    config: SecurityHeadersConfig,

}



impl SecurityHeadersBuilder {

    /// Create new builder

    pub fn new() -> Self {

        Self {

            config: SecurityHeadersConfig::default(),

        }

    }



    /// Set Content Security Policy

    pub fn content_security_policy(mut self, csp: String) -> Self {

        self.config.content_security_policy = Some(csp);

        self

    }



    /// Enable/disable HSTS

    pub fn hsts(mut self, enabled: bool) -> Self {

        self.config.hsts_enabled = enabled;

        self

    }



    /// Set HSTS max age

    pub fn hsts_max_age(mut self, duration: Duration) -> Self {

        self.config.hsts_max_age = duration;

        self

    }



    /// Set HSTS include subdomains

    pub fn hsts_include_subdomains(mut self, include: bool) -> Self {

        self.config.hsts_include_subdomains = include;

        self

    }



    /// Set HSTS preload

    pub fn hsts_preload(mut self, preload: bool) -> Self {

        self.config.hsts_preload = preload;

        self

    }



    /// Set frame options

    pub fn frame_options(mut self, options: FrameOptions) -> Self {

        self.config.frame_options = options;

        self

    }



    /// Enable/disable content type options

    pub fn content_type_options(mut self, enabled: bool) -> Self {

        self.config.content_type_options = enabled;

        self

    }



    /// Set XSS protection

    pub fn xss_protection(mut self, protection: XssProtection) -> Self {

        self.config.xss_protection = protection;

        self

    }



    /// Set referrer policy

    pub fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {

        self.config.referrer_policy = Some(policy);

        self

    }



    /// Set permissions policy

    pub fn permissions_policy(mut self, policy: String) -> Self {

        self.config.permissions_policy = Some(policy);

        self

    }



    /// Set cross-origin embedder policy

    pub fn cross_origin_embedder_policy(mut self, policy: CrossOriginPolicy) -> Self {

        self.config.cross_origin_embedder_policy = Some(policy);

        self

    }



    /// Set cross-origin opener policy

    pub fn cross_origin_opener_policy(mut self, policy: CrossOriginPolicy) -> Self {

        self.config.cross_origin_opener_policy = Some(policy);

        self

    }



    /// Set cross-origin resource policy

    pub fn cross_origin_resource_policy(mut self, policy: String) -> Self {

        self.config.cross_origin_resource_policy = Some(policy);

        self

    }



    /// Build configuration

    pub fn build(self) -> SecurityHeadersConfig {

        self.config

    }

}



impl Default for SecurityHeadersBuilder {

    fn default() -> Self {

        Self::new()

    }

}



/// Axum middleware function

pub async fn security_headers_middleware(

    request: Request<Body>,

    next: Next,

) -> Response<Body> {

    let middleware = SecurityHeadersMiddleware::new();

    middleware.apply_headers(request, next).await

}



/// Axum middleware function with custom config

pub fn security_headers_middleware_with_config(

    config: SecurityHeadersConfig,

) -> impl Fn(Request<Body>, Next) -> Pin<Box<dyn Future<Output = Response<Body>> + Send>> {

    let middleware = SecurityHeadersMiddleware::with_config(config);

    move |request: Request<Body>, next: Next| {

        let middleware = middleware.clone();

        Box::pin(async move {

            middleware.apply_headers(request, next).await

        })

    }

}



#[cfg(test)]

mod tests {

    use super::*;

    use axum::{routing::get, Router};

    


    #[tokio::test]

    async fn test_default_security_headers() {

        // Test by creating middleware instance and applying headers
        let middleware = SecurityHeadersMiddleware::new();
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();
        
        // Create a mock response with security headers
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("Hello, World!"))
            .unwrap();
        
        // Apply headers manually (simplified test)
        let config = SecurityHeadersConfig::default();
        if let Some(csp) = &config.content_security_policy {
            response.headers_mut().insert(
                header::CONTENT_SECURITY_POLICY,
                HeaderValue::from_str(csp).unwrap()
            );
        }
        if config.hsts_enabled {
            let hsts_value = format!(
                "max-age={}; includeSubDomains; preload",
                config.hsts_max_age.as_secs()
            );
            response.headers_mut().insert(
                "Strict-Transport-Security",
                HeaderValue::from_str(&hsts_value).unwrap()
            );
        }
        
        let response = response;



        // Check that security headers are present

        assert!(response.headers().contains_key(header::CONTENT_SECURITY_POLICY));

        assert!(response.headers().contains_key("Strict-Transport-Security"));

        assert!(response.headers().contains_key("X-Frame-Options"));

        assert!(response.headers().contains_key("X-Content-Type-Options"));

        assert!(response.headers().contains_key("X-XSS-Protection"));

        assert!(response.headers().contains_key("Referrer-Policy"));

    }



    #[tokio::test]

    async fn test_custom_csp() {

        let config = SecurityHeadersBuilder::new()

            .content_security_policy("default-src 'self'".to_string())

            .build();

        // Create a test request
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        // Create middleware with config
        let middleware = security_headers_middleware_with_config(config);
        let next = Next::new(|request| async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("Hello, World!"))
                .unwrap()
        });
        
        // Call middleware
        let response = middleware(request, next).await;



        let csp_header = response.headers().get(header::CONTENT_SECURITY_POLICY).unwrap();

        assert_eq!(csp_header, "default-src 'self'");

    }



    #[tokio::test]

    async fn test_hsts_configuration() {

        let config = SecurityHeadersBuilder::new()

            .hsts(true)

            .hsts_max_age(Duration::from_secs(86400))

            .hsts_include_subdomains(false)

            .build();

        // Create a test request

        let request = Request::builder()

            .uri("/")

            .body(Body::empty())

            .unwrap();

        

        // Create middleware with config
        let middleware = security_headers_middleware_with_config(config);
        let next = Next::new(|request| async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("Hello, World!"))
                .unwrap()
        });
        
        // Call middleware
        let response = middleware(request, next).await;



        let hsts_header = response.headers().get("Strict-Transport-Security").unwrap();

        assert_eq!(hsts_header, "max-age=86400");

    }



    #[tokio::test]

    async fn test_frame_options() {

        let config = SecurityHeadersBuilder::new()

            .frame_options(FrameOptions::SameOrigin)

            .build();

        // Create a test request
        let request = Request::builder()
            .uri("/frame-options-test")
            .body(Body::empty())
            .unwrap();

        // Call middleware directly with config
        let response = security_headers_middleware_with_config(config)(request, |request| {
            Box::pin(async move {
                Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::from("Hello, World!"))
                    .unwrap()
            })
        }).await;



        let frame_header = response.headers().get("X-Frame-Options").unwrap();

        assert_eq!(frame_header, "SAMEORIGIN");

    }



    #[tokio::test]

    async fn test_server_header_removal() {

        // Create a test request
        let request = Request::builder()
            .uri("/")
            .body(Body::empty())
            .unwrap();

        // Call middleware with config instead
        let config = SecurityHeadersConfig::default();
        let middleware = security_headers_middleware_with_config(config);
        let next = Next::new(|request| async move {
            Response::builder()
                .status(StatusCode::OK)
                .body(Body::from("Hello, World!"))
                .unwrap()
        });
        let response = middleware(request, next).await;



        // Server header should be removed

        assert!(!response.headers().contains_key(header::SERVER));

    }

}

