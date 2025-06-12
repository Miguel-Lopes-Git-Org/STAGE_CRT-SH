# 🔐 crt.sh API

<p align="center">
  <img src="https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi" alt="FastAPI">
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python">
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker">
</p>

A powerful **FastAPI-based REST API** for interacting with the **crt.sh Certificate Transparency database**. This API provides comprehensive certificate information, subdomain enumeration, security analysis, and certificate transparency insights.

---

## 🌟 Features

### 🔍 **Certificate Intelligence**
- **Multi-criteria Search**: SHA-1/SHA-256 fingerprints, organization, email, serial number
- **Detailed Certificate Parsing**: Complete X.509 certificate information extraction
- **Certificate Authority Analysis**: Comprehensive CA information and trust relationships
- **Transparency Logs**: Full CT log tracking and verification

### 🌐 **Subdomain Discovery**
- **Automated Enumeration**: Discover all subdomains for target domains
- **Smart Filtering**: Subdomain-only results with duplicate removal
- **Chronological Ordering**: Sort certificates by issue date
- **Latest Certificate Tracking**: Find most recent certificates per subdomain

### 🛡️ **Security Analysis**
- **Anomaly Detection**: Identify suspicious certificates and patterns
- **Expiration Monitoring**: Track expired and soon-to-expire certificates
- **Revocation Status**: OCSP and CRL validation checking
- **Trust Store Analysis**: Cross-platform trust verification

### ⚡ **High Performance**
- **Batch Processing**: Handle multiple domains simultaneously
- **Rate Limiting**: Built-in protection for crt.sh service limits
- **Parallel Processing**: Optimized concurrent request handling
- **Comprehensive Error Handling**: Robust error management and recovery

---

## 🚀 Quick Start

### Project Structure

```
crt-sh-api/
├── app/
│   ├── routes/
│   │   ├── certs.py
│   │   └── subdomains.py
│   ├── services/
│   │   ├── cert_fingerprint.py
│   │   ├── cert_id.py
│   │   ├── cert_parser.py
│   │   ├── cert_transparency.py
│   │   ├── get_all_cert.py
│   │   ├── get_ca.py
│   │   ├── revocation.py
│   │   └── search.py
│   ├── auth.py
│   ├── main.py
│   └── .env
├── .gitignore
├── Dockerfile
├── requirements.txt
└── README.md
```

### Prerequisites
- 🐍 **Python 3.8+**
- 📦 **pip** or **poetry** for dependency management
- 🐳 **Docker** (optional)

### Installation

#### 📥 Standard Installation
```bash
# Clone the repository
git clone <repository-url>
cd "crt.sh"

# Install dependencies
pip install -r requirements.txt

# Run the application
fastapi run --reload --host 0.0.0.0 --port 8000
```

#### 🐳 Docker Installation
```bash
# Build and run with Docker
docker build -t crtsh-api .
docker run -p 8000:8000 crtsh-api
```

### 🔗 Access the API
- **API Endpoints**: `http://localhost:8000`
- **Interactive Documentation**: `http://localhost:8000/docs`
- **OpenAPI Schema**: `http://localhost:8000/openapi.json`

---

## 🔑 API Key & Environment Configuration

To access any API endpoint, you must provide a valid API key.  
The `.env` file **must be configured** with your API key as follows:

```
API_KEY=your_secret_api_key
```

You must include this key in your requests using the HTTP header:

```
X-API-KEY: your_secret_api_key
```

---

## 📚 API Documentation

### 🌐 Subdomain Operations

#### `GET /domains/{domain}/subdomains`
**🔍 Discover all subdomains for a target domain**

Retrieves comprehensive subdomain certificates from the crt.sh database, automatically filtering for subdomains only and removing duplicates.

**Parameters:**
- `domain` (string): Target domain name (e.g., `example.com`)

**Response Example:**
```json
{
  "subdomains": [
    {
      "crt_id": "18961771644",
      "logged_at": "2025-06-11",
      "not_before": "2025-06-11",
      "not_after": "2025-09-09",
      "common_name": "api.example.com",
      "matching_identities": "api.example.com",
      "issuer_name": "C=US, O=Let's Encrypt, CN=E6"
    }
  ]
}
```

---

#### `GET /domains/{domain}/subdomains/{subdomain}/certs`
**🎯 Get certificate ID for specific subdomain**

Finds and returns the crt.sh certificate ID for a specific subdomain, enabling detailed certificate analysis.

**Parameters:**
- `domain` (string): Parent domain name
- `subdomain` (string): Specific subdomain to analyze

**Response Example:**
```json
{
  "crt_sh_id": "18961771644"
}
```

---

#### `GET /domains/{domain}/subdomains/{subdomain}/latest`
**⏰ Retrieve most recent subdomain certificate**

Returns the latest certificate issued for a specific subdomain based on the `not_before` date.

**Response Example:**
```json
{
  "last_cert": {
    "domain": "api.example.com",
    "id": "123456789",
    "logged_at": "2024-12-15",
    "not_before": "2024-12-15",
    "not_after": "2025-03-15"
  }
}
```

---

#### `POST /domains/{domain}/subdomains/ordered`
**📅 Get certificates ordered by issue date**

Returns all subdomain certificates sorted chronologically by issue date, with optional reverse ordering.

**Request Body:**
```json
{
  "revert": false
}
```

**Response Example:**
```json
{
  "certs": {
    "www.example.com": {
      "id": "987654321",
      "logged_at": "2024-12-01",
      "not_before": "2024-12-01",
      "not_after": "2025-03-01"
    },
    "api.example.com": {
      "id": "123456789",
      "logged_at": "2024-11-15",
      "not_before": "2024-11-15",
      "not_after": "2025-02-15"
    }
  }
}
```

---

#### `GET /domains/{domain}/anomalies`
**🚨 Detect certificate security anomalies**

Analyzes domain certificates to identify potential security issues including self-signed certificates, expired certificates, and other suspicious patterns.

**Response Example:**
```json
{
  "self_signed": {
    "test.example.com": {
      "id": "111222333",
      "logged_at": "2024-08-15",
      "not_before": "2024-08-15",
      "not_after": "2024-11-15",
      "issuer": "Self-Signed CA"
    }
  },
  "expired": {
    "old.example.com": {
      "id": "777888999",
      "logged_at": "2023-06-01",
      "not_before": "2023-06-01",
      "not_after": "2023-09-01"
    }
  }
}
```

---

#### `POST /domains/aggregate`
**🔄 Batch process multiple domains**

Efficiently processes multiple domains simultaneously with built-in rate limiting and parallel processing.

**Request Body:**
```json
{
  "domains": ["example.com", "test.org", "demo.net"]
}
```

**Response Example:**
```json
{
  "aggregated_domains": [
    {
      "domain": "example.com",
      "subdomains": [
        {
          "crt_id": "123456789",
          "common_name": "www.example.com",
          "not_before": "2024-12-01",
          "not_after": "2025-03-01"
        }
      ]
    },
    {
      "domain": "test.org",
      "subdomains": [
        {
          "crt_id": "456789123",
          "common_name": "mail.test.org",
          "not_before": "2024-10-01",
          "not_after": "2025-01-01"
        }
      ]
    }
  ]
}
```

---

### 🔐 Certificate Operations

#### `GET /certs/{certificate_id}`
**📋 Get comprehensive certificate details**

Retrieves complete certificate information including subject, issuer, extensions, validity periods, and digital signatures.

**Parameters:**
- `certificate_id` (string): crt.sh certificate ID

**Response Includes:**
- ✅ **Certificate subject and issuer information**
- ⏱️ **Validity periods and serial numbers**
- 🔑 **Public key information and algorithms**
- 🏷️ **X.509v3 extensions (Key Usage, SAN, etc.)**
- 📜 **Certificate policies and constraints**
- ✍️ **Digital signature information**

**Response Example:**
```json
{
  "Certificate": {
    "Version": "3 (0x2)",
    "Serial Number": "04:a1:b2:c3:d4:e5:f6:78:90:ab:cd:ef:12:34:56:78",
    "Signature Algorithm": "sha256WithRSAEncryption",
    "Issuer": {
      "C": "US",
      "O": "DigiCert Inc",
      "CN": "DigiCert SHA2 Secure Server CA"
    },
    "Validity": {
      "Not Before": "Dec 15 00:00:00 2024 GMT",
      "Not After": "Mar 15 23:59:59 2025 GMT"
    },
    "Subject": {
      "CN": "example.com"
    },
    "X509v3 extensions": {
      "X509v3 Subject Alternative Name": [
        "DNS:example.com",
        "DNS:www.example.com"
      ]
    }
  }
}
```

---

#### `POST /certs/search`
**🔍 Advanced certificate search**

Powerful multi-criteria certificate search supporting various search types and comprehensive result formatting.

**Supported Search Types:**

| Search Type | Description | Example Value |
|-------------|-------------|---------------|
| `SHA1` | SHA-1 fingerprint | `A1B2C3D4E5F6789012345678901234567890ABCD` |
| `SHA256` | SHA-256 fingerprint | `1234567890ABCDEF...` |
| `organisation` | Organization name | `Google Inc` |
| `email` | Email address | `admin@example.com` |
| `serialNumber` | Certificate serial | `04:a1:b2:c3:d4:e5:f6` |
| `CA` | Certificate Authority ID | `16418` |

**Request Body:**
```json
{
  "search": "SHA256",
  "value": "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
}
```

**Hash Search Response:**
```json
{
  "crt_sh_id": "123456789",
  "certificate_transparency": [
    {
      "timestamp": "2024-12-15 14:30:42 UTC",
      "entry_number": "123456789",
      "log_operator": "Google",
      "log_url": "https://ct.googleapis.com/logs/us1/argon2024h2"
    }
  ],
  "revocation": [
    {
      "mechanism": "OCSP",
      "provider": "DigiCert",
      "status": "Good",
      "revocation_date": null,
      "last_checked": "2024-12-20 10:30:15"
    }
  ],
  "certificate_fingerprint": {
    "sha1": "A1B2C3D4E5F6789012345678901234567890ABCD",
    "sha256": "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
  }
}
```

**Organization/Email Search Response:**
```json
{
  "certificates": [
    {
      "crt_id": "123456789",
      "common_name": "example.com",
      "issuer_name": "DigiCert Inc",
      "not_before": "2024-12-15",
      "not_after": "2025-03-15"
    }
  ]
}
```

**CA Search Response:**
```json
{
  "ca_id": "16418",
  "Subject": {
    "C": "US",
    "O": "DigiCert Inc",
    "CN": "DigiCert SHA2 Secure Server CA"
  },
  "certificates": [...],
  "Population": {
    "Certificates": {
      "Unexpired": "1,234,567",
      "Expired": "2,345,678",
      "Total": "3,580,245"
    }
  },
  "Trust": {
    "Server Authentication": {
      "Microsoft": "Yes",
      "Mozilla": "Yes",
      "Apple": "Yes"
    }
  }
}
```

---

## 🛠️ Configuration

### Environment Variables
Create a `.env` file in the project root:

```bash
# crt.sh Configuration
BASE_URL=https://crt.sh

# API Configuration
API_PORT=8000
API_HOST=0.0.0.0

# Rate Limiting
BATCH_SIZE=5
BATCH_DELAY=60

# Logging
LOG_LEVEL=INFO
```

---

## 📊 Rate Limiting & Performance

### 🚦 Built-in Rate Limiting
- **Batch Processing**: 5 domains per batch
- **Inter-batch Delay**: 60 seconds between batches

---

## 🔧 Error Handling

The API uses standard HTTP status codes with detailed error messages:

| Status Code | Description | Example |
|-------------|-------------|---------|
| `200` | ✅ Success | Request completed successfully |
| `400` | ❌ Bad Request | Invalid parameters or malformed request |
| `404` | 🔍 Not Found | Certificate or domain not found |
| `422` | ⚠️ Validation Error | Parameter validation failed |
| `429` | 🚫 Rate Limited | Too many requests, retry after delay |
| `500` | 💥 Server Error | Internal processing error |

**Error Response Format:**
```json
{
  "detail": "Certificate with ID '123456789' not found",
  "error_code": "CERT_NOT_FOUND",
  "timestamp": "2024-12-20T10:30:15Z"
}
```

---

## 🐳 Docker Support

### Quick Docker Setup
```bash
# Build the image
docker build -t crtsh-api .

# Run the container
docker run -d \
  --name crtsh-api \
  -p 8000:8000 \
  -e BASE_URL=https://crt.sh \
  crtsh-api

# Check logs
docker logs crtsh-api
```

### Docker Compose
```yaml
version: '3.8'
services:
  crtsh-api:
    build: .
    ports:
      - "8000:8000"
    environment:
      - BASE_URL=https://crt.sh
      - API_PORT=8000
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
```

---

## 🧪 Testing

### Manual Testing
```bash
# Health check
curl http://localhost:8000/health

# Get subdomains
curl http://localhost:8000/domains/example.com/subdomains

# Search certificates
curl -X POST http://localhost:8000/certs/search \
  -H "Content-Type: application/json" \
  -d '{"search": "organisation", "value": "Google Inc"}'
```

### Automated Testing
```bash
# Run tests
python -m pytest tests/

# With coverage
python -m pytest tests/ --cov=app --cov-report=html
```

---

## 👥 Authors

Made by Miguel LOPES and Clément DUMAS
