package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
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
	prefixes := []string{
		"lo", "docker", "br-", "veth", "tun", "tap", "ppp", "wg", "zt", "tailscale",
		"vmnet", "vboxnet", "br",
	}
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
	providers := []string{
		"https://api.ipify.org",
		"https://checkip.amazonaws.com",
		"https://ifconfig.me/ip",
	}
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
	base := strings.Join([]string{
		hostname,
		strings.Join(macs, ","),
		runtime.GOOS + "/" + runtime.GOARCH,
	}, "|")
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
	info := Info{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

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

func main() {
	http.HandleFunc("/get-info", handler)
	fmt.Println("listening on http://localhost:8011/get-info")
	if err := http.ListenAndServe(":8011", nil); err != nil {
		panic(err)
	}
}
