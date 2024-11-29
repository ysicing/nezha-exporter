package collector

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	serverStatus = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nezha",
			Name:      "info",
			Help:      "Nezha Agent info",
		},
		[]string{"name", "tag", "id", "version", "private", "ipv4", "ipv6"},
	)
	memory = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: "nezha",
			Name:      "memory",
			Help:      "Memory",
		},
		[]string{"name", "tag", "id", "private", "type"}, // type: used, total
	)
)

type CollectConfig struct {
	Host  string
	Token string
}

func init() {
	prometheus.MustRegister(serverStatus, memory)
}

func Start(config CollectConfig) {
	for {
		if err := Collect(config); err != nil {
			fmt.Printf("Error collecting metrics: %v\n", err)
		}
		time.Sleep(15 * time.Second)
	}
}

type NezhaResponse struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Result  []ServerDetails `json:"result"`
}

type ServerDetails struct {
	ID           int    `json:"id"`
	Name         string `json:"name"`
	Tag          string `json:"tag,omitempty"`
	LastActive   int64  `json:"last_active"`
	IPv4         string `json:"ipv4"`
	IPv6         string `json:"ipv6"`
	ValidIP      string `json:"valid_ip"`
	HideForGuest bool   `json:"hide_for_guest"`
	Host         Host   `json:"host"`
	Status       Status `json:"status"`
}

type Host struct {
	Platform        string   `json:"Platform"`
	PlatformVersion string   `json:"PlatformVersion"`
	CPU             []string `json:"CPU"`
	MemTotal        int64    `json:"MemTotal"`
	DiskTotal       int64    `json:"DiskTotal"`
	SwapTotal       int64    `json:"SwapTotal"`
	Arch            string   `json:"Arch"`
	Virtualization  string   `json:"Virtualization"`
	BootTime        int64    `json:"BootTime"`
	CountryCode     string   `json:"CountryCode"`
	Version         string   `json:"Version"`
}

type Status struct {
	CPU            float64 `json:"CPU"`
	MemUsed        int64   `json:"MemUsed"`
	SwapUsed       int64   `json:"SwapUsed"`
	DiskUsed       int64   `json:"DiskUsed"`
	NetInTransfer  int64   `json:"NetInTransfer"`
	NetOutTransfer int64   `json:"NetOutTransfer"`
	NetInSpeed     int64   `json:"NetInSpeed"`
	NetOutSpeed    int64   `json:"NetOutSpeed"`
	Uptime         int64   `json:"Uptime"`
	Load1          float64 `json:"Load1"`
	Load5          float64 `json:"Load5"`
	Load15         float64 `json:"Load15"`
	TcpConnCount   int     `json:"TcpConnCount"`
	UdpConnCount   int     `json:"UdpConnCount"`
	ProcessCount   int     `json:"ProcessCount"`
}

func Collect(config CollectConfig) error {
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", fmt.Sprintf("%s/api/v1/server/details", config.Host), nil)
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", config.Token)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var respData NezhaResponse
	if err := json.NewDecoder(resp.Body).Decode(&respData); err != nil {
		return err
	}
	for _, server := range respData.Result {
		tag := server.Tag
		if len(tag) == 0 {
			tag = "默认"
		}
		ipv4 := true
		if len(server.IPv4) == 0 {
			ipv4 = false
		}
		ipv6 := true
		if len(server.IPv6) == 0 {
			ipv6 = false
		}
		serverStatus.WithLabelValues(server.Name, tag, fmt.Sprintf("%d", server.ID), server.Host.Version, fmt.Sprintf("%t", server.HideForGuest), fmt.Sprintf("%t", ipv4), fmt.Sprintf("%t", ipv6)).Set(1)
		memory.WithLabelValues(server.Name, tag, fmt.Sprintf("%d", server.ID), fmt.Sprintf("%t", server.HideForGuest), "used").Set(float64(server.Status.MemUsed))
		memory.WithLabelValues(server.Name, tag, fmt.Sprintf("%d", server.ID), fmt.Sprintf("%t", server.HideForGuest), "total").Set(float64(server.Host.MemTotal))
	}
	return nil
}
