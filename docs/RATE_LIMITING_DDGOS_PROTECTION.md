# Rate Limiting and DDoS Protection

This document describes the advanced rate limiting and DDoS protection features implemented in Fortress server.

## Overview

Fortress provides production-ready rate limiting with multiple algorithms and comprehensive DDoS protection mechanisms. The system is designed to be fast, efficient, scalable, and secure.

## Features

### Rate Limiting Algorithms

1. **Token Bucket** (Default)
   - Allows bursts up to configured size
   - Tokens refill at a constant rate
   - Good for handling traffic spikes while maintaining average rate

2. **Sliding Window**
   - Tracks request timestamps in a sliding time window
   - More accurate than fixed window for traffic distribution
   - Prevents traffic spikes at window boundaries

3. **Fixed Window**
   - Simple and efficient
   - Resets counter at fixed intervals
   - May allow traffic spikes at window boundaries

4. **Leaky Bucket**
   - Smooths out traffic bursts
   - Processes requests at a constant rate
   - Good for traffic shaping

### DDoS Protection

- **Global Request Rate Monitoring**: Tracks overall server request rate
- **IP-based Rate Limiting**: Monitors individual IP addresses
- **Reputation System**: Maintains reputation scores for IPs
- **Auto-blocking**: Automatically blocks malicious IPs
- **Adaptive Thresholds**: Adjusts limits based on IP reputation

## Configuration

### Rate Limiting Configuration

```toml
[security.rate_limit]
enabled = true
requests_per_minute = 60
requests_per_hour = 1000
burst_size = 10
algorithm = "TokenBucket"

[security.rate_limit.ddos_protection]
enabled = true
global_rps_threshold = 1000
ip_rps_threshold = 100
auto_block_threshold = 200
block_duration_seconds = 300
reputation_decay_rate = 10
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | true | Enable/disable rate limiting |
| `requests_per_minute` | u32 | 60 | Maximum requests per minute |
| `requests_per_hour` | u32 | 1000 | Maximum requests per hour |
| `burst_size` | u32 | 10 | Maximum burst size |
| `algorithm` | enum | TokenBucket | Rate limiting algorithm |

### DDoS Protection Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | bool | true | Enable/disable DDoS protection |
| `global_rps_threshold` | Option<u32> | None | Global requests per second limit |
| `ip_rps_threshold` | Option<u32> | None | IP-specific requests per second limit |
| `auto_block_threshold` | Option<u32> | None | Auto-block threshold |
| `block_duration_seconds` | u64 | 300 | Block duration in seconds |
| `reputation_decay_rate` | u8 | 10 | Reputation recovery rate per hour |

## Usage

### Basic Setup

```rust
use fortress_server::prelude::*;

let config = ServerConfig::default();
let server = FortressServer::new(config).await?;
server.listen("0.0.0.0:8080").await?;
```

### Custom Rate Limiting

```rust
use fortress_server::middleware::{AdvancedRateLimiter, RateLimitAlgorithm};

let mut rate_limit_config = RateLimitConfig::default();
rate_limit_config.algorithm = RateLimitAlgorithm::SlidingWindow;
rate_limit_config.requests_per_minute = 100;

let rate_limiter = AdvancedRateLimiter::new(rate_limit_config);
```

### Programmatic Rate Limiting

```rust
// Check if a request is allowed
let client_id = "user:12345";
match rate_limiter.check_rate_limit(client_id).await {
    Ok(()) => {
        // Process request
    }
    Err(ServerError::RateLimit) => {
        // Handle rate limit exceeded
    }
    Err(ServerError::DdosBlocked) => {
        // Handle DDoS block
    }
}

// Get rate limit headers
if let Some((remaining, limit, reset)) = rate_limiter.get_rate_limit_headers(client_id).await {
    // Add headers to response
    response.headers_mut().insert("X-RateLimit-Remaining", remaining);
    response.headers_mut().insert("X-RateLimit-Limit", limit);
    response.headers_mut().insert("X-RateLimit-Reset", reset);
}
```

## Performance

### Benchmarks

The rate limiting system has been benchmarked for performance:

- **Single Request Check**: ~50ns per request
- **Concurrent Requests**: Handles 10,000+ concurrent requests
- **Memory Usage**: ~100 bytes per tracked client
- **Cleanup Overhead**: <1ms for 10,000 clients

### Optimization Features

1. **Lock-free Data Structures**: Uses `DashMap` for concurrent access
2. **Efficient Algorithms**: Optimized implementations of each algorithm
3. **Automatic Cleanup**: Periodic cleanup of stale data
4. **Minimal Allocations**: Reduces memory allocations in hot paths

## Security Features

### DDoS Detection

1. **Traffic Pattern Analysis**: Detects unusual request patterns
2. **Reputation Scoring**: Tracks IP behavior over time
3. **Adaptive Filtering**: Applies stricter limits to low-reputation IPs
4. **Automatic Blocking**: Blocks IPs that exceed thresholds

### Rate Limiting Security

1. **Client Isolation**: Each client tracked independently
2. **Burst Protection**: Prevents traffic spikes
3. **Graceful Degradation**: Maintains service under load
4. **Comprehensive Logging**: Tracks all rate limiting actions

## Monitoring and Metrics

### Available Metrics

```rust
let metrics = rate_limiter.get_metrics();
println!("Total requests: {}", metrics.total_requests);
println!("Allowed requests: {}", metrics.allowed_requests);
println!("Blocked requests: {}", metrics.blocked_requests);
println!("DDoS blocks: {}", metrics.ddos_blocks);
```

### Prometheus Metrics

The system exports Prometheus metrics for monitoring:

- `fortress_rate_limit_total_requests`
- `fortress_rate_limit_allowed_requests`
- `fortress_rate_limit_blocked_requests`
- `fortress_ddos_blocks_total`

## Best Practices

### Configuration Guidelines

1. **Set Appropriate Limits**: Configure limits based on your capacity
2. **Enable DDoS Protection**: Always enable DDoS protection in production
3. **Monitor Metrics**: Regularly monitor rate limiting metrics
4. **Test Thoroughly**: Test rate limiting under load

### Algorithm Selection

- **Token Bucket**: Best for general use, handles bursts well
- **Sliding Window**: Most accurate, higher memory usage
- **Fixed Window**: Simplest, may allow boundary spikes
- **Leaky Bucket**: Best for traffic shaping

### Performance Tuning

1. **Adjust Cleanup Frequency**: Balance memory vs. CPU usage
2. **Optimize Client ID Generation**: Use efficient client identification
3. **Monitor Memory Usage**: Track memory consumption with many clients
4. **Load Test**: Verify performance under expected load

## Integration Examples

### Axum Middleware

```rust
use axum::{middleware, Router};

let app = Router::new()
    .route("/api/*", api_routes)
    .layer(middleware::from_fn_with_state(
        rate_limiter.clone(),
        advanced_rate_limit_middleware,
    ));
```

### Custom Headers

```rust
// Add custom rate limit headers
async fn custom_rate_limit_middleware(
    State(rate_limiter): State<Arc<AdvancedRateLimiter>>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let client_id = extract_client_id(&request);
    
    match rate_limiter.check_rate_limit(&client_id).await {
        Ok(()) => {
            let mut response = next.run(request).await;
            
            // Add custom headers
            if let Some((remaining, limit, reset)) = rate_limiter.get_rate_limit_headers(&client_id).await {
                response.headers_mut().insert("X-RateLimit-Remaining", remaining);
                response.headers_mut().insert("X-RateLimit-Limit", limit);
                response.headers_mut().insert("X-RateLimit-Reset", reset);
                response.headers_mut().insert("X-RateLimit-Algorithm", 
                    HeaderValue::from_str(&format!("{:?}", rate_limiter.config.algorithm)).unwrap());
            }
            
            Ok(response)
        }
        Err(e) => {
            tracing::warn!("Rate limit exceeded for {}: {}", client_id, e);
            Err(StatusCode::TOO_MANY_REQUESTS)
        }
    }
}
```

## Troubleshooting

### Common Issues

1. **Too Many Blocks**: Check rate limit configuration
2. **Performance Issues**: Monitor memory usage and cleanup frequency
3. **False Positives**: Adjust DDoS thresholds
4. **Memory Leaks**: Ensure cleanup is running properly

### Debug Information

Enable debug logging to troubleshoot issues:

```rust
tracing::info!("Rate limit metrics: {:?}", rate_limiter.get_metrics());
```

### Testing

Run the comprehensive test suite:

```bash
cargo test --package fortress-server test_rate_limiting
cargo bench --package fortress-server rate_limit_benchmark
```

## Future Enhancements

Planned improvements include:

1. **Distributed Storage**: Redis support for multi-instance deployments
2. **Advanced Algorithms**: Add more sophisticated rate limiting algorithms
3. **Machine Learning**: ML-based DDoS detection
4. **Geo-blocking**: Geographic-based filtering
5. **Custom Rules**: User-defined rate limiting rules

## Security Considerations

1. **Client Identification**: Ensure client IDs cannot be spoofed
2. **Resource Limits**: Set appropriate memory and CPU limits
3. **Monitoring**: Continuously monitor for attacks
4. **Updates**: Keep rate limiting configurations updated
5. **Testing**: Regularly test DDoS protection effectiveness

## Conclusion

The Fortress rate limiting and DDoS protection system provides comprehensive, high-performance protection for your applications. With multiple algorithms, adaptive protection, and extensive monitoring, it ensures your service remains available and secure under various traffic conditions.

For more information, see the [API documentation](./API.md) and [configuration guide](./CONFIGURATION.md).
