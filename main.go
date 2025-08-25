package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

type IfaceInfo struct {
	Name       string   `json:"name"`
	Index      int      `json:"index"`
	MAC        string   `json:"mac"`
	IPs        []string `json:"ips"`
	IsUp       bool     `json:"is_up"`
	IsLoopback bool     `json:"is_loopback"`
}

type Info struct {
	Timestamp         string      `json:"timestamp"`
	Hostname          string      `json:"hostname"`
	Username          string      `json:"username"`
	OS                string      `json:"os"`
	Arch              string      `json:"arch"`
	MachineID         string      `json:"machine_id,omitempty"`
	ProductUUID       string      `json:"product_uuid,omitempty"`
	ProcessorID       string      `json:"processor_id,omitempty"`
	LaptopMAC         string      `json:"device_mac,omitempty"`
	Interfaces        []IfaceInfo `json:"interfaces"`
	PrimaryInterface  *IfaceInfo  `json:"primary_interface,omitempty"`
	PublicIP          string      `json:"public_ip,omitempty"`
	DeviceFingerprint string      `json:"device_fingerprint"`
	Error             string      `json:"error,omitempty"`
}

var (
	flagInstall = flag.Bool("install-autostart", false, "")
	flagRemove  = flag.Bool("remove-autostart", false, "")
)

func gatherInterfacesFiltered() ([]IfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []IfaceInfo
	for _, ifc := range ifaces {
		isLoop := (ifc.Flags & net.FlagLoopback) != 0
		isUp := (ifc.Flags & net.FlagUp) != 0
		if isLoop || isVirtualOrTransient(ifc.Name) {
			continue
		}
		addrs, _ := ifc.Addrs()
		var ips []string
		for _, a := range addrs {
			if ipNet, ok := a.(*net.IPNet); ok {
				if v4 := ipNet.IP.To4(); v4 != nil {
					ips = append(ips, v4.String())
				}
			}
		}
		out = append(out, IfaceInfo{
			Name:       ifc.Name,
			Index:      ifc.Index,
			MAC:        ifc.HardwareAddr.String(),
			IPs:        ips,
			IsUp:       isUp,
			IsLoopback: isLoop,
		})
	}
	return out, nil
}

func isVirtualOrTransient(name string) bool {
	n := strings.ToLower(name)
	prefixes := []string{"lo", "docker", "br-", "veth", "tun", "tap", "ppp", "wg", "zt", "tailscale", "vmnet", "vboxnet", "br"}
	for _, p := range prefixes {
		if n == p || strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

func choosePrimary(ifaces []IfaceInfo) *IfaceInfo {
	for _, i := range ifaces {
		if i.IsUp && len(i.IPs) > 0 {
			cp := i
			return &cp
		}
	}
	if len(ifaces) > 0 {
		cp := ifaces[0]
		return &cp
	}
	return nil
}

func getPublicIP() (string, error) {
	providers := []string{"https://api.ipify.org", "https://checkip.amazonaws.com", "https://ifconfig.me/ip"}
	client := &http.Client{Timeout: 4 * time.Second}
	for _, url := range providers {
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			continue
		}
		ip := strings.TrimSpace(string(body))
		if ip != "" {
			return ip, nil
		}
	}
	return "", errors.New("no public IP provider reachable")
}

func buildFingerprint(hostname string, macs []string) string {
	sort.Strings(macs)
	base := strings.Join([]string{hostname, strings.Join(macs, ","), runtime.GOOS + "/" + runtime.GOARCH}, "|")
	sum := sha256.Sum256([]byte(base))
	return hex.EncodeToString(sum[:])
}

func getProcessorID() string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	switch runtime.GOOS {
	case "windows":
		out, err := exec.CommandContext(ctx, "wmic", "cpu", "get", "ProcessorId").CombinedOutput()
		if err == nil {
			lines := strings.Split(string(out), "\n")
			for _, ln := range lines {
				ln = strings.TrimSpace(ln)
				if ln == "" || strings.EqualFold(ln, "ProcessorId") {
					continue
				}
				return ln
			}
		}
		out, err = exec.CommandContext(ctx, "powershell", "-NoProfile", "-Command", "(Get-CimInstance Win32_Processor).ProcessorId").CombinedOutput()
		if err == nil {
			s := strings.TrimSpace(string(out))
			if s != "" {
				return s
			}
		}
	case "darwin":
		out, err := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice").CombinedOutput()
		if err == nil {
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.Contains(ln, "IOPlatformUUID") {
					parts := strings.Split(ln, "=")
					if len(parts) == 2 {
						return strings.Trim(strings.TrimSpace(parts[1]), "\" ")
					}
				}
			}
		}
		out, err = exec.CommandContext(ctx, "system_profiler", "SPHardwareDataType").CombinedOutput()
		if err == nil {
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.Contains(ln, "Serial Number") {
					parts := strings.Split(ln, ":")
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
	case "linux":
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, ln := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ln)), "serial") {
					parts := strings.Split(ln, ":")
					if len(parts) == 2 {
						return strings.TrimSpace(parts[1])
					}
				}
			}
		}
		if b, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			s := strings.TrimSpace(string(b))
			if s != "" {
				return s
			}
		}
	}
	return ""
}

func guessLaptopMAC(ifaces []IfaceInfo, primary *IfaceInfo) string {
	var candidates []IfaceInfo
	for _, i := range ifaces {
		n := strings.ToLower(i.Name)
		if strings.HasPrefix(n, "en0") || strings.HasPrefix(n, "en1") || strings.HasPrefix(n, "wlan") || strings.HasPrefix(n, "wl") || strings.Contains(n, "wifi") {
			candidates = append(candidates, i)
		}
		if strings.Contains(strings.ToLower(n), "wi-fi") {
			candidates = append(candidates, i)
		}
	}
	for _, c := range candidates {
		if c.IsUp && c.MAC != "" {
			return c.MAC
		}
	}
	for _, c := range candidates {
		if c.MAC != "" {
			return c.MAC
		}
	}
	if primary != nil && primary.MAC != "" {
		return primary.MAC
	}
	for _, i := range ifaces {
		if i.MAC != "" {
			return i.MAC
		}
	}
	return ""
}

func getInfo() Info {
	info := Info{Timestamp: time.Now().UTC().Format(time.RFC3339), OS: runtime.GOOS, Arch: runtime.GOARCH}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	if u, err := user.Current(); err == nil {
		name := u.Username
		if name == "" {
			name = u.Name
		}
		info.Username = name
	}
	if runtime.GOOS == "linux" {
		if mid, err := os.ReadFile("/etc/machine-id"); err == nil {
			info.MachineID = strings.TrimSpace(string(mid))
		}
		if pu, err := os.ReadFile("/sys/class/dmi/id/product_uuid"); err == nil {
			info.ProductUUID = strings.TrimSpace(string(pu))
		}
	}
	ifaces, err := gatherInterfacesFiltered()
	if err == nil {
		info.Interfaces = ifaces
	}
	if p := choosePrimary(info.Interfaces); p != nil {
		info.PrimaryInterface = p
	}
	if ip, err := getPublicIP(); err == nil {
		info.PublicIP = ip
	}
	var macs []string
	for _, i := range info.Interfaces {
		if i.MAC != "" {
			macs = append(macs, strings.ToLower(i.MAC))
		}
	}
	info.DeviceFingerprint = buildFingerprint(info.Hostname, macs)
	info.ProcessorID = getProcessorID()
	info.LaptopMAC = guessLaptopMAC(info.Interfaces, info.PrimaryInterface)
	return info
}

func handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	info := getInfo()
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(info)
}

func exePath() string {
	p, _ := os.Executable()
	pp, _ := filepath.EvalSymlinks(p)
	return pp
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func ensureAutostartInstall() error {
	switch runtime.GOOS {
	case "windows":
		return installAutostartWindows()
	case "linux":
		return installAutostartLinux()
	default:
		return fmt.Errorf("autostart not implemented for %s", runtime.GOOS)
	}
}

func ensureAutostartRemove() error {
	switch runtime.GOOS {
	case "windows":
		return removeAutostartWindows()
	case "linux":
		return removeAutostartLinux()
	default:
		return fmt.Errorf("autostart not implemented for %s", runtime.GOOS)
	}
}

func installAutostartWindows() error {
	ep := exePath()
	err := run("schtasks.exe", "/Create", "/TN", "DeviceInfoAPI", "/SC", "ONSTART", "/TR", fmt.Sprintf(`"%s"`, ep), "/RL", "HIGHEST", "/RU", "SYSTEM", "/F")
	if err == nil {
		_ = run("schtasks.exe", "/Run", "/TN", "DeviceInfoAPI")
		return nil
	}
	err = run("schtasks.exe", "/Create", "/TN", "DeviceInfoAPI", "/SC", "ONLOGON", "/TR", fmt.Sprintf(`"%s"`, ep), "/RL", "HIGHEST", "/F")
	if err == nil {
		_ = run("schtasks.exe", "/Run", "/TN", "DeviceInfoAPI")
		return nil
	}
	return fmt.Errorf("failed to create scheduled task: %v", err)
}

func removeAutostartWindows() error {
	return run("schtasks.exe", "/Delete", "/TN", "DeviceInfoAPI", "/F")
}

func copyFile(src, dst string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Chmod(dst, mode)
}

func installAutostartLinux() error {
	ep := exePath()
	tmp := filepath.Join(os.TempDir(), "device-info.service")
	unitSys := `[Unit]
				Description=Device Info API
				After=network-online.target
				Wants=network-online.target

				[Service]
				ExecStart=/opt/device-info/device-info
				Restart=always
				RestartSec=5
				WorkingDirectory=/opt/device-info

				[Install]
				WantedBy=multi-user.target
				`
	if err := os.WriteFile(tmp, []byte(unitSys), 0644); err == nil {
		if err := run("sudo", "install", "-D", ep, "/opt/device-info/device-info"); err == nil {
			if err := run("sudo", "mv", tmp, "/etc/systemd/system/device-info.service"); err == nil {
				_ = run("sudo", "systemctl", "daemon-reload")
				_ = run("sudo", "systemctl", "enable", "--now", "device-info.service")
				return nil
			}
		}
	}
	home, _ := os.UserHomeDir()
	dest := filepath.Join(home, ".local", "bin", "device-info")
	if err := copyFile(ep, dest, 0755); err != nil {
		return err
	}
	unitUser := `[Unit]
				Description=Device Info API (user)
				After=network-online.target

				[Service]
				ExecStart=` + dest + `
				Restart=always
				RestartSec=5
				WorkingDirectory=` + home + `

				[Install]
				WantedBy=default.target
				`
	userUnitPath := filepath.Join(home, ".config", "systemd", "user", "device-info.service")
	if err := os.MkdirAll(filepath.Dir(userUnitPath), 0755); err == nil {
		if err := os.WriteFile(userUnitPath, []byte(unitUser), 0644); err == nil {
			_ = run("systemctl", "--user", "daemon-reload")
			if err := run("systemctl", "--user", "enable", "--now", "device-info.service"); err == nil {
				return nil
			}
		}
	}
	desktopDir := filepath.Join(home, ".config", "autostart")
	_ = os.MkdirAll(desktopDir, 0755)
	desktop := `[Desktop Entry]
				Type=Application
				Name=Device Info API
				Exec=` + dest + `
				X-GNOME-Autostart-enabled=true
				`
	_ = os.WriteFile(filepath.Join(desktopDir, "device-info.desktop"), []byte(desktop), 0644)
	line := fmt.Sprintf(`@reboot "%s" >/tmp/device-info.log 2>&1`, dest)
	_ = exec.Command("bash", "-c", `(crontab -l 2>/dev/null; echo '`+line+`') | crontab -`).Run()
	return nil
}

func removeAutostartLinux() error {
	_ = run("sudo", "systemctl", "disable", "--now", "device-info.service")
	_ = run("sudo", "rm", "-f", "/etc/systemd/system/device-info.service")
	_ = run("sudo", "rm", "-f", "/opt/device-info/device-info")
	_ = run("sudo", "systemctl", "daemon-reload")
	home, _ := os.UserHomeDir()
	_ = run("systemctl", "--user", "disable", "--now", "device-info.service")
	_ = os.Remove(filepath.Join(home, ".config", "systemd", "user", "device-info.service"))
	_ = os.Remove(filepath.Join(home, ".config", "autostart", "device-info.desktop"))
	_ = exec.Command("bash", "-c", `crontab -l 2>/dev/null | grep -v device-info | crontab -`).Run()
	_ = os.Remove(filepath.Join(home, ".local", "bin", "device-info"))
	return nil
}

func main() {
	flag.Parse()
	if *flagInstall {
		if err := ensureAutostartInstall(); err != nil {
			fmt.Println(err)
		}
		return
	}
	if *flagRemove {
		if err := ensureAutostartRemove(); err != nil {
			fmt.Println(err)
		}
		return
	}
	http.HandleFunc("/get-device-info", handler)
	fmt.Println("listening on http://localhost:58080/get-device-info")
	if err := http.ListenAndServe(":58080", nil); err != nil {
		panic(err)
	}
}
