package service

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/repository"
)

type botIPRangeState struct {
	networks []*net.IPNet
}

type BotIPRangeFetcher struct {
	repo   *repository.BotIPRangeRepository
	appCfg *config.AppConfig
	client *http.Client

	state unsafe.Pointer // *botIPRangeState
	mu    sync.Mutex
}

func NewBotIPRangeFetcher(repo *repository.BotIPRangeRepository) *BotIPRangeFetcher {
	f := &BotIPRangeFetcher{
		repo:   repo,
		appCfg: config.GetAppConfig(),
		client: &http.Client{Timeout: 30 * time.Second},
	}

	initial := f.loadNetworks()
	atomic.StorePointer(&f.state, unsafe.Pointer(initial))

	go f.periodicSync()
	go f.periodicReload()

	return f
}

func (f *BotIPRangeFetcher) loadNetworks() *botIPRangeState {
	ranges, err := f.repo.GetEnabled()
	if err != nil {
		f.appCfg.LogWarn("[BotIPRange] Failed to load ranges: %v", err)
		return &botIPRangeState{}
	}

	var networks []*net.IPNet
	for _, r := range ranges {
		for _, cidr := range r.IPRanges {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			if !strings.Contains(cidr, "/") {
				if strings.Contains(cidr, ":") {
					cidr += "/128"
				} else {
					cidr += "/32"
				}
			}
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			networks = append(networks, ipNet)
		}
	}

	f.appCfg.LogDebug("[BotIPRange] Loaded %d networks from %d providers", len(networks), len(ranges))
	return &botIPRangeState{networks: networks}
}

func (f *BotIPRangeFetcher) Contains(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	st := (*botIPRangeState)(atomic.LoadPointer(&f.state))
	if st == nil {
		return false
	}

	for _, network := range st.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func (f *BotIPRangeFetcher) FetchFromURL(url string) ([]string, error) {
	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read body failed: %w", err)
	}

	ipRanges := parseIPRangesFromBody(body)
	if len(ipRanges) == 0 {
		return nil, fmt.Errorf("no valid IP ranges found in response")
	}

	return ipRanges, nil
}

func (f *BotIPRangeFetcher) FetchSingle(id int, url string) {
	ipRanges, err := f.FetchFromURL(url)
	if err != nil {
		f.appCfg.LogWarn("[BotIPRange] Fetch failed for id=%d url=%s: %v", id, url, err)
		return
	}

	if err := f.repo.UpdateIPRanges(id, ipRanges); err != nil {
		f.appCfg.LogWarn("[BotIPRange] Update failed for id=%d: %v", id, err)
		return
	}

	f.appCfg.LogInfo("[BotIPRange] Synced id=%d: %d ranges from %s", id, len(ipRanges), url)
	f.reload()
}

func (f *BotIPRangeFetcher) periodicSync() {
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		f.syncAll()
	}
}

func (f *BotIPRangeFetcher) periodicReload() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		f.reload()
	}
}

func (f *BotIPRangeFetcher) syncAll() {
	ranges, err := f.repo.GetEnabled()
	if err != nil {
		f.appCfg.LogWarn("[BotIPRange] Failed to load for sync: %v", err)
		return
	}

	for _, r := range ranges {
		if r.SourceType != "json_url" || r.URL == "" {
			continue
		}
		f.FetchSingle(r.ID, r.URL)
	}
}

func (f *BotIPRangeFetcher) reload() {
	next := f.loadNetworks()
	atomic.StorePointer(&f.state, unsafe.Pointer(next))
}

func parseIPRangesFromBody(body []byte) []string {
	// Try JSON format first (Google/Bing style)
	var jsonResp struct {
		Prefixes []struct {
			IPv4Prefix string `json:"ipv4Prefix"`
			IPv6Prefix string `json:"ipv6Prefix"`
		} `json:"prefixes"`
	}

	if err := json.Unmarshal(body, &jsonResp); err == nil && len(jsonResp.Prefixes) > 0 {
		var ranges []string
		for _, p := range jsonResp.Prefixes {
			if p.IPv4Prefix != "" {
				ranges = append(ranges, p.IPv4Prefix)
			}
			if p.IPv6Prefix != "" {
				ranges = append(ranges, p.IPv6Prefix)
			}
		}
		return ranges
	}

	// Try plain text format (Yandex style: one CIDR per line)
	lines := strings.Split(string(body), "\n")
	var ranges []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if isValidCIDROrIP(line) {
			ranges = append(ranges, line)
		}
	}

	return ranges
}

func isValidCIDROrIP(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}
