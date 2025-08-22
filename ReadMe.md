# sys-info-http — README

A tiny Go HTTP service that returns useful system + network details as JSON (hostname, user, OS/arch, active interfaces, public IP, simple device fingerprint, etc.).

## Features

* Enumerates non-virtual network interfaces (MAC, IPv4s, up/down).
* Picks a “primary” interface.
* Fetches your public IP via multiple providers.
* Gathers host facts (hostname, username, GOOS/GOARCH, Linux machine-id / product UUID).
* Attempts a processor ID (best-effort per OS).
* Builds a simple device fingerprint (SHA-256 of hostname + MACs + OS/arch).
* Single endpoint: `GET /get-info`.

> ⚠️ **Privacy note:** This exposes potentially sensitive identifiers (MAC, UUIDs, public IP). Run it locally or on trusted networks only. Don’t expose it publicly without access controls.

---

## Requirements

* Go 1.20+ (recommended).
* Network egress allowed (to resolve public IP).

---

## Build

### Linux / macOS

```bash
git clone <your-repo-url> sys-info-http
cd sys-info-http
go build -o sys-info-http .
```

### Windows (PowerShell)

```powershell
git clone <your-repo-url> sys-info-http
cd sys-info-http
go build -o sys-info-http.exe .
```

### Cross-compile examples

```bash
# Linux → macOS (ARM64)
GOOS=darwin GOARCH=arm64 go build -o sys-info-http-darwin-arm64 .
# Linux → Windows (x64)
GOOS=windows GOARCH=amd64 go build -o sys-info-http.exe .
```

---

## Run

```bash
./sys-info-http
# or on Windows:
.\sys-info-http.exe
```

You’ll see:

```
listening on http://localhost:8011/get-info
```

By default it listens on `:8011`.

> Tip: If another process is using 8011, free it or change the port in code (`ListenAndServe`).

---

## Use

### cURL

```bash
curl http://localhost:8011/get-info
```

### HTTPie

```bash
http :8011/get-info
```

### PowerShell

```powershell
Invoke-RestMethod http://localhost:8011/get-info | ConvertTo-Json -Depth 5
```

**Response (example, trimmed):**

```json
{
  "timestamp": "2025-08-22T09:15:30Z",
  "hostname": "my-host",
  "username": "alice",
  "os": "linux",
  "arch": "amd64",
  "machine_id": "2a7c...c9f",
  "product_uuid": "D4E3...-UUID",
  "processor_id": "BFEBFBFF000906EA",
  "device_mac": "a1:b2:c3:d4:e5:f6",
  "interfaces": [
    {
      "name": "eth0",
      "index": 2,
      "mac": "a1:b2:c3:d4:e5:f6",
      "ips": ["192.168.1.10"],
      "is_up": true,
      "is_loopback": false
    }
  ],
  "primary_interface": {
    "name": "eth0",
    "index": 2,
    "mac": "a1:b2:c3:d4:e5:f6",
    "ips": ["192.168.1.10"],
    "is_up": true,
    "is_loopback": false
  },
  "public_ip": "203.0.113.25",
  "device_fingerprint": "0f4c1a...f0d"
}
```

**HTTP headers set:**

* `Content-Type: application/json; charset=utf-8`
* `Cache-Control: no-store`
* `Access-Control-Allow-Origin: *` (CORS open; lock this down if exposing publicly)

---

## Configuration

This sample is zero-config. To adjust:

* **Port:** change the string in `http.ListenAndServe(":8011", nil)`.
* **Public IP providers:** edit the list in `getPublicIP()`.
* **Interface filtering:** tweak `isVirtualOrTransient()` prefixes.
* **Timeouts:** update the HTTP client timeout and command timeouts.

---

## Docker (optional)

**Dockerfile**

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/sys-info-http .

FROM alpine:3.20
COPY --from=build /out/sys-info-http /usr/local/bin/sys-info-http
EXPOSE 8011
CMD ["sys-info-http"]
```

**Build & run**

```bash
docker build -t sys-info-http .
docker run --rm -p 8011:8011 --network host sys-info-http
# On Mac/Windows you may omit --network host and use -p 8011:8011 only
```

---

## Systemd (Linux, optional)

`/etc/systemd/system/sys-info-http.service`

```ini
[Unit]
Description=Sys Info HTTP
After=network-online.target

[Service]
ExecStart=/usr/local/bin/sys-info-http
Restart=on-failure
User=nobody
Group=nogroup
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now sys-info-http
```

---

## Security best practices

* Run behind a reverse proxy with auth (e.g., Basic Auth, mTLS).
* Restrict listener to localhost (e.g., `127.0.0.1:8011`) if only for local use.
* Consider removing fields you don’t need (MACs/UUIDs).
* Review CORS policy before internet exposure.

---

## Troubleshooting

* **Port already in use:** choose another port or stop the conflicting service.
* **Public IP empty:** egress blocked or providers unreachable; check firewall/proxy.
* **No interfaces listed:** the process lacks permission or is in a restricted container; relax container net settings.
* **Slow response:** public IP provider timeout (4s); reduce providers or timeouts.

---

## Project structure

Single file (as provided) with:

* `main()` – sets up HTTP server and route.
* `handler()` – encodes `Info` as JSON.
* Helpers for interfaces, public IP, fingerprint, processor ID, and heuristics.

---

## License

Choose and add a LICENSE (MIT/Apache-2.0/BSD-3-Clause/etc.) to the repo.

---

## Quick start (copy/paste)

```bash
go build -o sys-info-http .
./sys-info-http
curl :8011/get-info | jq
```
