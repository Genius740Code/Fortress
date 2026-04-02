# TLS Test Certificates for WebSocket Testing

These are self-signed certificates for testing TLS/WSS functionality in development.

## Generate Test Certificates

To generate new test certificates:

```bash
# Generate private key
openssl genrsa -out test-key.pem 2048

# Generate certificate signing request
openssl req -new -key test-key.pem -out test-csr.pem

# Generate self-signed certificate
openssl x509 -req -days 365 -in test-csr.pem -signkey test-key.pem -out test-cert.pem

# Clean up CSR
rm test-csr.pem
```

## Certificate Details

- **Common Name**: localhost
- **Valid for**: 365 days
- **Usage**: TLS Web Server Authentication
- **Key Size**: 2048 bits

## Usage in Tests

The integration tests will automatically skip TLS tests if these certificates are not found.
Place the certificates in this directory to enable TLS testing:

- `test-cert.pem` - TLS certificate
- `test-key.pem` - TLS private key

## Security Warning

These are self-signed certificates for development/testing only.
DO NOT use these certificates in production environments.
