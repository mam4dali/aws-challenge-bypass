# AWS WAF Bypass Proxy

A reverse-proxy microservice that mirrors any website behind **AWS WAF** and automatically solves WAF challenges (captchas) so you can scrape without being blocked.

## Features

- **Full mirror** of any target site — all paths, query strings and content types
- **All HTTP methods**: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS
- **Automatic AWS WAF challenge solving** using browser fingerprint emulation
- **Chrome TLS fingerprint impersonation** via `curl_cffi`
- **WAF token caching** — solves the challenge once, reuses the token for subsequent requests
- **HTTP proxy support** — route all upstream traffic through a proxy
- **Raw pass-through** — response body is returned without modification
- **Cookie forwarding** — client cookies are forwarded to the target site

## Project Structure

```
aws-challenge-bypass/
├── app/
│   ├── __init__.py
│   ├── config.py          # Environment configuration loader
│   ├── main.py            # FastAPI app + proxy logic
│   ├── solver.py          # AWS WAF challenge solver
│   └── cookie_store.py    # Thread-safe WAF cookie cache
├── tests/
│   ├── __init__.py
│   ├── test_cookie_store.py
│   ├── test_solver_utils.py
│   └── test_proxy.py
├── install/
│   ├── install.bat        # Windows install script
│   └── install.sh         # macOS/Linux install script
├── run/
│   ├── run.bat            # Windows run script
│   └── run.sh             # macOS/Linux run script
├── .env.example           # Example environment variables
├── requirements.txt
├── run.py                 # Python entry point (reads HOST/PORT from .env)
└── README.md
```

---

## Setup

### Prerequisites

- **Python 3.10+** is required.

### 1. Clone the repository

```bash
git clone <repo-url>
cd aws-challenge-bypass
```

### 2. Quick Install (recommended)

The install script creates a venv, installs dependencies, and copies `.env.example` to `.env`:

#### macOS / Linux

```bash
./install/install.sh
```

#### Windows

Double-click `install\install.bat` or run:

```cmd
install\install.bat
```

### Manual Install

<details>
<summary>Click to expand manual steps</summary>

#### Create virtual environment

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate

# Windows (CMD)
python -m venv venv
venv\Scripts\activate.bat

# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
```

> **Note:** On Windows, if you get an execution policy error, run:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

#### Install dependencies

```bash
pip install -r requirements.txt
```

#### Configure environment

```bash
cp .env.example .env
```

</details>

### 3. Configure environment variables

Edit `.env` to customize your settings:

```ini
# Server
HOST=0.0.0.0
PORT=8080
LOG_LEVEL=INFO

# Target site (e.g. https://www.imdb.com)
TARGET_ORIGIN=https://www.imdb.com
IMPERSONATE=chrome
USER_AGENT=Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/145.0.0.0 Safari/537.36

# Proxy (leave empty to disable)
HTTP_PROXY=

# SSL (leave empty to disable HTTPS)
SSL_CERTFILE=
SSL_KEYFILE=
```

#### Environment Variables Reference

| Variable | Default | Description |
|---|---|---|
| `HOST` | `0.0.0.0` | Server bind address |
| `PORT` | `8080` | Server port |
| `LOG_LEVEL` | `INFO` | Logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |
| `TARGET_ORIGIN` | `https://www.imdb.com` | Upstream target URL (can be changed for other sites) |
| `IMPERSONATE` | `chrome` | TLS fingerprint to impersonate |
| `USER_AGENT` | Chrome 145 UA string | User-Agent header for upstream requests |
| `HTTP_PROXY` | *(empty)* | HTTP/SOCKS proxy URL (e.g. `http://user:pass@host:port` or `socks5://host:port`) |
| `SSL_CERTFILE` | *(empty)* | Path to SSL certificate file (e.g. `certs/cert.pem`) |
| `SSL_KEYFILE` | *(empty)* | Path to SSL private key file (e.g. `certs/key.pem`) |

---

## Running the Server

#### macOS / Linux

```bash
./run/run.sh
```

#### Windows

Double-click `run\run.bat` or run:

```cmd
run\run.bat
```

> **Tip:** You can add `run\run.bat` to Windows Startup folder to auto-start the server on boot.

By default the proxy starts at `http://localhost:8080`. You can change `HOST` and `PORT` in your `.env` file.

Alternatively, run manually:

```bash
source venv/bin/activate   # macOS/Linux
python run.py
```

### Usage

Instead of requesting the target site directly:
```
https://www.imdb.com/title/tt0111161/
```

Use the proxy:
```
http://localhost:8080/title/tt0111161/
```

#### Examples

```bash
# Fetch a movie page
curl http://localhost:8080/title/tt0111161/

# Fetch a person page
curl http://localhost:8080/name/nm0000138/

# Fetch the homepage
curl http://localhost:8080/

# HEAD request
curl -I http://localhost:8080/title/tt0111161/

# Search
curl "http://localhost:8080/find/?q=inception&ref_=nv_sr_sm"
```

---

## Running Tests

```bash
# Make sure venv is activated
source venv/bin/activate   # macOS/Linux

# Run all tests
python -m pytest tests/ -v

# Run a specific test file
python -m pytest tests/test_cookie_store.py -v
python -m pytest tests/test_solver_utils.py -v
python -m pytest tests/test_proxy.py -v
```

Tests are fully offline — they use mocks and don't make real network requests.

---

## Using an HTTP Proxy

To route all upstream traffic through a proxy, set `HTTP_PROXY` in your `.env`:

```ini
# HTTP proxy
HTTP_PROXY=http://username:password@proxy-host:8888

# SOCKS5 proxy
HTTP_PROXY=socks5://proxy-host:1080
```

This applies to both the main proxy requests and the WAF challenge solver requests.

---

## Enabling HTTPS (SSL)

To serve over HTTPS, set the certificate and key paths in `.env`:

```ini
SSL_CERTFILE=certs/cert.pem
SSL_KEYFILE=certs/key.pem
```

To generate a self-signed certificate for testing:

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes -subj "/CN=localhost"
```

The server will then be available at `https://localhost:8080`.

---

## How It Works

1. Client sends a request to the proxy (e.g. `GET /title/tt0111161/`)
2. The proxy forwards it to `https://www.imdb.com/title/tt0111161/` using `curl_cffi` with Chrome TLS fingerprint impersonation
3. If the target returns **HTTP 202** with a WAF challenge page:
   - The solver extracts `window.gokuProps` from the HTML
   - Builds a browser fingerprint and solves the proof-of-work challenge
   - Submits the solution and receives an `aws-waf-token`
   - The token is cached and the original request is retried
4. The response (HTML, JSON, images, etc.) is returned to the client as-is

---

## License

The AWS WAF solver is based on [tveronesi/imdbinfo](https://github.com/tveronesi/imdbinfo) (MIT License).
