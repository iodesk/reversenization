package app

import (
	"fmt"
	"net"
	"net/http"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Upstream struct {
	Scheme  string `json:"scheme"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Weight  int    `json:"weight"`
	Enabled bool   `json:"enabled"`
	Healthy bool   `json:"healthy,omitempty"`
}

type AppConfig struct {
	Description string     `json:"description,omitempty"`
	Upstreams   []Upstream `json:"upstreams"`
	LBMethod    string     `json:"lb_method"`

	ListenPort int `json:"listen_port,omitempty"`

	UseGlobalRateLimit bool               `json:"use_global_rate_limit"`
	RateLimits         []RateLimitProfile `json:"rate_limits,omitempty"`

	UseGlobalWAF bool        `json:"use_global_waf"`
	WAF          *WAFProfile `json:"waf,omitempty"`

	UseGlobalBot bool        `json:"use_global_bot"`
	Bot          *BotProfile `json:"bot,omitempty"`

	RedirectHTTPS bool              `json:"redirect_https"`
	HealthCheck   HealthCheckConfig `json:"health_check"`

	Advanced AdvancedConfig `json:"advanced"`
}

type HealthCheckConfig struct {
	Enabled   bool   `json:"enabled"`
	Path      string `json:"path"`
	Interval  int    `json:"interval"`
	Threshold int    `json:"threshold"`
}


type ResponseHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type AdvancedConfig struct {
	ListenIPv6 bool `json:"listen_ipv6"`

	AllowWebSocket bool `json:"allow_websocket"`

	ModifyHostHeader    bool   `json:"modify_host_header"`
	HostHeaderValue     string `json:"host_header_value"`
	PassXForwardedHost  bool   `json:"pass_x_forwarded_host"`
	PassXForwardedProto bool   `json:"pass_x_forwarded_proto"`

	AllowInsecureSSL bool `json:"allow_insecure_ssl"`

	TrustedProxies []string `json:"trusted_proxies,omitempty"`

	ConnectTimeout int `json:"connect_timeout"`
	ReadTimeout    int `json:"read_timeout"`
	SendTimeout    int `json:"send_timeout"`

	ProxyBuffering bool `json:"proxy_buffering"`

	AddHeaders []ResponseHeader `json:"add_headers,omitempty"`

	RequestSizeLimit int64 `json:"request_size_limit"`

	CORS CORSConfig `json:"cors"`

	Cache CacheConfig `json:"cache"`
}

type CORSConfig struct {
	Enabled        bool     `json:"enabled"`
	AllowOrigins   []string `json:"allow_origins,omitempty"`
	AllowMethods   []string `json:"allow_methods,omitempty"`
	AllowHeaders   []string `json:"allow_headers,omitempty"`
	ExposeHeaders  []string `json:"expose_headers,omitempty"`
	AllowCreds     bool     `json:"allow_credentials"`
	MaxAge         int      `json:"max_age"`
}

type CacheConfig struct {
	Enabled bool `json:"enabled"`
	TTL     int  `json:"ttl"`
}


type RateLimitProfile struct {
	Type         string `json:"type"`
	Duration     int    `json:"duration"`
	Count        int    `json:"count"`
	Action       string `json:"action"`
	ChallengeSec int    `json:"challenge_sec"`
}


type WAFProfile struct {
	ScoreThreshold          int    `json:"score_threshold"`
	OutboundScoreThreshold  int    `json:"outbound_score_threshold,omitempty"`
}


type BotProfile struct {
	EnableChallenge bool   `json:"enable_challenge"`
	ChallengeType   string `json:"challenge_type"`
	ChallengeExpiry int    `json:"challenge_expiry"`
	ChallengeWait   int    `json:"challenge_wait"`
}


type App struct {
	ID          string
	Domain      string
	Description string

	Config AppConfig

	UnderAttackMode bool

	CreatedAt time.Time
	UpdatedAt time.Time
}

// rrCounters holds per-app atomic round-robin counters (keyed by app ID).
var rrCounters sync.Map

func (a *App) IsStream() bool {
	if len(a.Config.Upstreams) == 0 {
		return false
	}
	scheme := a.Config.Upstreams[0].Scheme
	return scheme == "tcp" || scheme == "udp"
}

func (a *App) StreamScheme() string {
	if len(a.Config.Upstreams) == 0 {
		return ""
	}
	return a.Config.Upstreams[0].Scheme
}

func StreamPortMin() int {
	if val := os.Getenv("STREAM_PORT_MIN"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n
		}
	}
	return 10000
}

func StreamPortMax() int {
	if val := os.Getenv("STREAM_PORT_MAX"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			return n
		}
	}
	return 19999
}

func (a *App) PickUpstream(clientIP string) *Upstream {
	active := make([]Upstream, 0, len(a.Config.Upstreams))
	for _, u := range a.Config.Upstreams {
		if !u.Enabled {
			continue
		}
		// Skip unhealthy upstreams only when health check is configured.
		if a.Config.HealthCheck.Enabled && !u.Healthy {
			continue
		}
		active = append(active, u)
	}
	// Fallback: if all upstreams are unhealthy, use all enabled ones.
	if len(active) == 0 {
		for _, u := range a.Config.Upstreams {
			if u.Enabled {
				active = append(active, u)
			}
		}
	}
	if len(active) == 0 {
		return nil
	}
	if len(active) == 1 {
		return &active[0]
	}

	switch a.Config.LBMethod {
	case "ip-hash":
		h := fnv.New32a()
		h.Write([]byte(clientIP))
		idx := int(h.Sum32()) % len(active)
		return &active[idx]

	case "least-conn":
		// Without real-time connection tracking, fall through to round-robin.
		fallthrough

	default: // round-robin
		val, _ := rrCounters.LoadOrStore(a.ID, new(uint64))
		counter := val.(*uint64)
		idx := int(atomic.AddUint64(counter, 1)-1) % len(active)
		return &active[idx]
	}
}



// ExtractClientIP returns the real client IP by walking X-Forwarded-For
// from the rightmost untrusted proxy. If no trusted proxies are configured,
// it falls back to the leftmost X-Forwarded-For value (backward compatible).
func (a *App) ExtractClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		// CF-Connecting-IP is set by nginx after Cloudflare, which we trust.
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return strings.TrimSpace(cfIP)
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}

	ips := strings.Split(xff, ",")
	trustedProxies := a.Config.Advanced.TrustedProxies

	if len(trustedProxies) == 0 {
		// No trusted proxy config: use leftmost (backward compatible with existing setup).
		return strings.TrimSpace(ips[0])
	}

	// Walk from right to left; rightmost non-trusted IP is the real client.
	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		trusted := false
		for _, cidr := range trustedProxies {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed != nil && network.Contains(parsed) {
				trusted = true
				break
			}
		}
		if !trusted {
			return ip
		}
	}

	// All IPs in the chain are trusted proxies; use leftmost as fallback.
	return strings.TrimSpace(ips[0])
}

// ExtractClientIPStatic is like ExtractClientIP but works with only trusted proxies list
// (no App needed — for call sites that may not have a resolved app yet).
func ExtractClientIPStatic(r *http.Request, trustedProxies []string) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff == "" {
		if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
			return strings.TrimSpace(cfIP)
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return r.RemoteAddr
		}
		return host
	}

	ips := strings.Split(xff, ",")
	if len(trustedProxies) == 0 {
		return strings.TrimSpace(ips[0])
	}

	for i := len(ips) - 1; i >= 0; i-- {
		ip := strings.TrimSpace(ips[i])
		trusted := false
		for _, cidr := range trustedProxies {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			parsed := net.ParseIP(ip)
			if parsed != nil && network.Contains(parsed) {
				trusted = true
				break
			}
		}
		if !trusted {
			return ip
		}
	}
	return strings.TrimSpace(ips[0])
}

func (a *App) Validate() error {
	if a.Domain == "" {
		return ErrInvalidDomain
	}
	if strings.HasPrefix(a.Domain, "http://") || strings.HasPrefix(a.Domain, "https://") {
		return fmt.Errorf("domain must not include scheme (http:// or https://)")
	}
	if strings.ContainsAny(a.Domain, " \t\n") {
		return fmt.Errorf("domain must not contain spaces")
	}
	if len(a.Config.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}

	for _, u := range a.Config.Upstreams {
		if u.Host == "" || u.Port <= 0 {
			return fmt.Errorf("invalid upstream host or port")
		}
		if u.Port > 65535 {
			return fmt.Errorf("upstream port must be between 1 and 65535")
		}
		if u.Scheme != "http" && u.Scheme != "https" && u.Scheme != "tcp" && u.Scheme != "udp" {
			return fmt.Errorf("invalid upstream scheme: %s", u.Scheme)
		}
		if u.Weight < 1 || u.Weight > 100 {
			return fmt.Errorf("upstream weight must be between 1 and 100")
		}
	}

	if a.IsStream() {
		minPort := StreamPortMin()
		maxPort := StreamPortMax()
		if a.Config.ListenPort != 0 && (a.Config.ListenPort < minPort || a.Config.ListenPort > maxPort) {
			return fmt.Errorf("listen_port must be between %d and %d", minPort, maxPort)
		}
	}

	activeCount := 0
	for _, u := range a.Config.Upstreams {
		if u.Enabled {
			activeCount++
		}
	}
	if activeCount == 0 {
		return fmt.Errorf("at least one upstream must be enabled")
	}

	if len(a.Config.Upstreams) > 1 {
		if a.Config.LBMethod != "round-robin" && a.Config.LBMethod != "least-conn" && a.Config.LBMethod != "ip-hash" {
			return fmt.Errorf("invalid load balancing method: %s", a.Config.LBMethod)
		}
	}

	if !a.Config.UseGlobalRateLimit {
		for _, rl := range a.Config.RateLimits {
			if rl.Duration <= 0 || rl.Count <= 0 {
				return ErrInvalidFloodConfig
			}
		}
	}

	if !a.Config.UseGlobalBot && a.Config.Bot != nil && a.Config.Bot.EnableChallenge {
		if a.Config.Bot.ChallengeType != "js" && a.Config.Bot.ChallengeType != "cookie" && a.Config.Bot.ChallengeType != "pow" {
			return ErrInvalidChallengeType
		}
		if a.Config.Bot.ChallengeExpiry <= 0 || a.Config.Bot.ChallengeWait <= 0 {
			return ErrInvalidChallengeConfig
		}
	}

	if !a.Config.UseGlobalWAF && a.Config.WAF != nil {
		if a.Config.WAF.ScoreThreshold <= 0 {
			return ErrInvalidWAFThreshold
		}
	}

	adv := a.Config.Advanced
	if adv.ConnectTimeout < 0 || adv.ConnectTimeout > 300 {
		return fmt.Errorf("connect_timeout must be between 0 and 300")
	}
	if adv.ReadTimeout < 0 || adv.ReadTimeout > 600 {
		return fmt.Errorf("read_timeout must be between 0 and 600")
	}
	if adv.SendTimeout < 0 || adv.SendTimeout > 600 {
		return fmt.Errorf("send_timeout must be between 0 and 600")
	}
	for _, h := range adv.AddHeaders {
		if strings.TrimSpace(h.Name) == "" {
			return fmt.Errorf("response header name must not be empty")
		}
	}
	if adv.RequestSizeLimit < 0 {
		return fmt.Errorf("request_size_limit must be >= 0")
	}
	if adv.Cache.Enabled && adv.Cache.TTL <= 0 {
		return fmt.Errorf("cache ttl must be > 0 when cache is enabled")
	}
	if a.Config.HealthCheck.Enabled {
		if a.Config.HealthCheck.Path == "" {
			a.Config.HealthCheck.Path = "/health"
		}
		if a.Config.HealthCheck.Interval <= 0 {
			a.Config.HealthCheck.Interval = 30
		}
		if a.Config.HealthCheck.Threshold <= 0 {
			a.Config.HealthCheck.Threshold = 3
		}
	}

	return nil
}
