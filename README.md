# TLS Server with Client Authentication

A Go-based web server that requires TLS client authentication. Clients must present a certificate signed by a trusted CA to access files.

## Features

- TLS server with mandatory client certificate authentication
- Configurable directory of trusted CA certificates
- File serving from a specified data directory
- Access granted only to clients with valid certificates

## Usage

```bash
# Start the server
./tlsserver -trust /path/to/trust/dir -data /path/to/data/dir -cert server.crt -key server.key

# Default values if not specified:
# -trust: ./trust
# -data: ./data
# -listen: :8443
# -cert: server.crt
# -key: server.key
```

## Setup Requirements

1. Generate a server certificate and key
2. Create a trust directory with CA certificates that will be trusted
3. Create a data directory with files to serve
4. Client certificates must be signed by one of the CAs in the trust directory

## Example Setup

### Server Certificate

```bash
# Generate private key for the server
openssl genrsa -out server.key 2048

# Generate a self-signed certificate for the server
openssl req -new -x509 -key server.key -out server.crt -days 365
```

### Client Certificate

```bash
# Generate CA key and certificate
openssl genrsa -out ca.key 2048
openssl req -new -x509 -key ca.key -out ca.crt -days 365

# Generate client key
openssl genrsa -out client.key 2048

# Generate client certificate signing request
openssl req -new -key client.key -out client.csr

# Sign client certificate with the CA
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client.crt -days 365
```

### Client Usage with curl

```bash
curl --cert client.crt --key client.key --cacert server.crt https://localhost:8443/
```

## Building

```bash
go build -o tlsserver
```