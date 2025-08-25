# sys-info-http 🚀

A tiny Go HTTP service that returns useful system + network details as JSON — hostname, user, OS/arch, active interfaces, public IP, simple device fingerprint, and more. Includes **self-install autostart** for Windows (Task Scheduler) and Linux (systemd user/system with desktop/cron fallbacks).

> 🔒 **Privacy:** This exposes identifiers (MACs, UUIDs, public IP). Run locally or on trusted networks. Lock down access if exposing beyond localhost.

---

## ✨ Features

* 🔎 Enumerates non-virtual network interfaces (MAC, IPv4s, up/down)
* 🎯 Picks a “primary” interface
* 🌐 Fetches public IP via multiple providers
* 🧰 Gathers host facts (hostname, username, GOOS/GOARCH, Linux machine-id / product UUID)
* 🧪 Attempts a processor ID (best-effort per OS)
* 🆔 Builds a simple device fingerprint (SHA-256 of hostname + MACs + OS/arch)
* 🛣️ Single endpoint: `GET /get-device-info`
* ⚙️ Autostart helpers:

  * `--install-autostart`
  * `--remove-autostart`

---

## 📦 Requirements

* Go 1.20+
* Outbound network allowed (for public IP resolution)

---

## 🛠️ Build

You can name the binary as you like; examples use `device-info`.

### Linux / macOS

```bash
go build -ldflags="-s -w" -o device-info .
```

### Windows (PowerShell)

```powershell
go build -ldflags="-s -w" -o device-info.exe .
```

### Cross-compile (from Linux/macOS)

```bash
# Windows x64
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o device-info-windows-amd64.exe .

# Linux x64
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o device-info-linux-amd64 .
```

---

## ▶️ Run

```bash
./device-info          # Linux/macOS
# or
.\device-info.exe      # Windows
```

You’ll see:

```
listening on http://localhost:58080/get-device-info
```

---

## 🧪 Use

### cURL

```bash
curl http://localhost:58080/get-device-info
```

### PowerShell

```powershell
Invoke-RestMethod http://localhost:58080/get-device-info | ConvertTo-Json -Depth 6
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
  "product_uuid": "D4E3-...-UUID",
  "processor_id": "BFEBFBFF000906EA",
  "device_mac": "a1:b2:c3:d4:e5:f6",
  "interfaces": [ { "...": "..." } ],
  "primary_interface": { "...": "..." },
  "public_ip": "203.0.113.25",
  "device_fingerprint": "0f4c1a...f0d"
}
```

HTTP headers:

* `Content-Type: application/json; charset=utf-8`
* `Cache-Control: no-store`
* `Access-Control-Allow-Origin: *` (adjust if exposing)

---

## ⚡ Autostart (self-install)

Run **once** with the flag; the app sets itself up to start on reboot and starts immediately.

### Linux

```bash
./device-info --install-autostart
```

Behavior:

* Tries system-wide systemd (copies to `/opt/device-info/device-info`, needs `sudo`)
* Else user-level systemd (`~/.local/bin/device-info` + `~/.config/systemd/user/device-info.service`)
* Else desktop autostart + crontab `@reboot` fallback

Remove:

```bash
./device-info --remove-autostart
```

Diagnostics:

```bash
systemctl status device-info.service
systemctl --user status device-info.service
journalctl -u device-info.service -b --no-pager -n 200
```

### Windows

```powershell
.\device-info.exe --install-autostart
```

Behavior:

* Creates Task Scheduler entry (tries SYSTEM @ startup; falls back to current user @ logon)

Remove:

```powershell
.\device-info.exe --remove-autostart
```

Verify:

```powershell
Get-ScheduledTask -TaskName DeviceInfoAPI | Format-List *
```

---

## 💾 Portable (USB) workflow

* Build binaries (`device-info-windows-amd64.exe`, `device-info-linux-amd64`)
* Copy to USB
* On the target machine, run **once** with `--install-autostart`
* After that, it starts on reboot (binary is copied to a stable path on Linux)

---

## 🔧 Configuration

* **Port / endpoint:** edit `main()` (`ListenAndServe(":58080", ...)` and route `/get-device-info`)
* **Bind interface:** switch to `"127.0.0.1:58080"` for local-only
* **Public IP providers:** edit the list in `getPublicIP()`
* **Interface filtering:** tweak `isVirtualOrTransient()` prefixes
* **Timeouts:** adjust HTTP client and command timeouts

---

## 🐳 Docker (optional)

```dockerfile
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -ldflags="-s -w" -o /out/device-info .

FROM alpine:3.20
COPY --from=build /out/device-info /usr/local/bin/device-info
EXPOSE 58080
CMD ["device-info"]
```

```bash
docker build -t device-info .
docker run --rm -p 58080:58080 device-info
```

---

## 🛡️ Security

* Prefer binding to `127.0.0.1:58080` if used locally
* If exposing, place behind a reverse proxy with auth or mTLS
* Remove fields you don’t need
* Review CORS before internet exposure

---

## 🧩 Troubleshooting

* **No autostart after reboot (Linux):** ensure a stable path (`/opt/...` or `~/.local/bin`); check `systemctl --user` availability or run with `sudo` for system service
* **USB path used:** autostart from USB won’t work pre-mount; run `--install-autostart`
* **Port in use:** change port or stop the conflicting service
* **Public IP empty:** outbound egress blocked
* **Few/no interfaces:** container/namespace restrictions

---

## 👤 Authors

* **bidhan948** ✨
