package handler

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/logger"
)

type AnalyticsHandler struct {
	logger *logger.Clickhouse
}

func NewAnalyticsHandler(logger *logger.Clickhouse) *AnalyticsHandler {
	return &AnalyticsHandler{logger: logger}
}

// validRanges defines all accepted range values for threat intel endpoints.
var validRanges = map[string]bool{
	"5min": true, "15min": true, "1h": true,
	"1d": true, "7d": true, "30d": true,
}

// rangeToWhereClause returns a ClickHouse WHERE time condition and a label format.
// Returns (whereExpr, labelFormat, bucketExpr, bucketCount, isMinute)
func rangeToWhereClause(rangeParam string) (where, labelFmt, bucketFn string, bucketCount int) {
	switch rangeParam {
	case "5min":
		return "ts >= now() - interval 5 minute", "15:04", "toStartOfMinute(ts)", 5
	case "15min":
		return "ts >= now() - interval 15 minute", "15:04", "toStartOfMinute(ts)", 15
	case "1h":
		return "ts >= now() - interval 1 hour", "15:04", "toStartOfMinute(ts)", 60
	case "1d":
		return "ts >= now() - interval 1 day", "15:04", "toStartOfHour(ts)", 24
	case "7d":
		return "ts >= now() - interval 7 day", "Jan 2", "toDate(ts)", 7
	case "30d":
		return "ts >= now() - interval 30 day", "Jan 2", "toDate(ts)", 30
	default:
		return "ts >= now() - interval 7 day", "Jan 2", "toDate(ts)", 7
	}
}

func validateRange(rangeParam string) bool {
	return validRanges[rangeParam]
}

// sanitizeAppID strips any character that isn't alphanumeric, dash, or underscore.
// App IDs are user-defined slugs — this prevents SQL injection via string interpolation.
func sanitizeAppID(id string) string {
	out := make([]byte, 0, len(id))
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			out = append(out, c)
		}
	}
	return string(out)
}

func formatLabelForRange(t time.Time, rangeParam string) string {
	switch rangeParam {
	case "5min", "15min", "1h", "1d":
		return t.Format("15:04")
	default:
		monthNames := []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
		return monthNames[t.Month()] + " " + t.Format("2")
	}
}

type TrafficDataPoint struct {
	Timestamp string `json:"timestamp"`
	Label     string `json:"label"`
	Allow     uint64 `json:"allow"`
	Block     uint64 `json:"block"`
	Challenge uint64 `json:"challenge"`
}

type TrafficAnalyticsResponse struct {
	Range   string             `json:"range"`
	Data    []TrafficDataPoint `json:"data"`
	Summary struct {
		Total     uint64 `json:"total"`
		Allow     uint64 `json:"allow"`
		Block     uint64 `json:"block"`
		BlockWAF  uint64 `json:"block_waf"`
		BlockBot  uint64 `json:"block_bot"`
		Challenge uint64 `json:"challenge"`
	} `json:"summary"`
}

type CacheHistoryPoint struct {
	Label     string  `json:"label"`
	CacheHit  uint64  `json:"cache_hit"`
	CacheMiss uint64  `json:"cache_miss"`
	HitRate   float64 `json:"hit_rate"`
}

type CacheAnalyticsResponse struct {
	Range   string              `json:"range"`
	Data    []CacheHistoryPoint `json:"data"`
	Summary struct {
		TotalHit  uint64  `json:"total_hit"`
		TotalMiss uint64  `json:"total_miss"`
		HitRate   float64 `json:"hit_rate"`
	} `json:"summary"`
}

func (h *AnalyticsHandler) GetCacheAnalytics(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if rangeParam != "1d" && rangeParam != "7d" && rangeParam != "30d" {
		respondError(w, http.StatusBadRequest, "Invalid range. Must be 1d, 7d, or 30d")
		return
	}

	var query, timeFormat string
	var days int

	switch rangeParam {
	case "1d":
		days, timeFormat = 1, "2006-01-02T15:00:00Z"
		query = `SELECT toStartOfHour(ts) as t, countIf(cache_hit=true), countIf(cache_hit=false)
			FROM waf_events WHERE ts >= now()-toIntervalDay(1) AND action IN ('block','challenge')
			GROUP BY t ORDER BY t ASC`
	case "7d":
		days, timeFormat = 7, "2006-01-02"
		query = `SELECT toDate(ts) as t, countIf(cache_hit=true), countIf(cache_hit=false)
			FROM waf_events WHERE ts >= now()-toIntervalDay(7) AND action IN ('block','challenge')
			GROUP BY t ORDER BY t ASC`
	case "30d":
		days, timeFormat = 30, "2006-01-02"
		query = `SELECT toDate(ts) as t, countIf(cache_hit=true), countIf(cache_hit=false)
			FROM waf_events WHERE ts >= now()-toIntervalDay(30) AND action IN ('block','challenge')
			GROUP BY t ORDER BY t ASC`
	}

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query cache analytics: "+err.Error())
		return
	}
	defer rows.Close()

	dataMap := make(map[string]*CacheHistoryPoint)
	var totalHit, totalMiss uint64

	for rows.Next() {
		var bucket time.Time
		var hits, misses uint64
		if err := rows.Scan(&bucket, &hits, &misses); err != nil {
			continue
		}
		key := bucket.Format(timeFormat)
		total := hits + misses
		var rate float64
		if total > 0 {
			rate = float64(hits) / float64(total) * 100
		}
		dataMap[key] = &CacheHistoryPoint{
			Label:     formatLabel(bucket, rangeParam),
			CacheHit:  hits,
			CacheMiss: misses,
			HitRate:   rate,
		}
		totalHit += hits
		totalMiss += misses
	}

	data := generateCacheTimeBuckets(rangeParam, days, dataMap, timeFormat)

	var summaryRate float64
	if totalHit+totalMiss > 0 {
		summaryRate = float64(totalHit) / float64(totalHit+totalMiss) * 100
	}

	resp := CacheAnalyticsResponse{Range: rangeParam, Data: data}
	resp.Summary.TotalHit = totalHit
	resp.Summary.TotalMiss = totalMiss
	resp.Summary.HitRate = summaryRate
	respondJSON(w, http.StatusOK, resp)
}

func generateCacheTimeBuckets(rangeParam string, days int, dataMap map[string]*CacheHistoryPoint, timeFormat string) []CacheHistoryPoint {
	var data []CacheHistoryPoint
	now := time.Now()

	if rangeParam == "1d" {
		for i := 23; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * time.Hour)
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
			if p, ok := dataMap[t.Format(timeFormat)]; ok {
				data = append(data, *p)
			} else {
				data = append(data, CacheHistoryPoint{Label: formatLabel(t, rangeParam)})
			}
		}
	} else {
		for i := days - 1; i >= 0; i-- {
			t := now.AddDate(0, 0, -i)
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
			if p, ok := dataMap[t.Format(timeFormat)]; ok {
				data = append(data, *p)
			} else {
				data = append(data, CacheHistoryPoint{Label: formatLabel(t, rangeParam)})
			}
		}
	}
	return data
}

func (h *AnalyticsHandler) GetTrafficAnalytics(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if rangeParam != "1d" && rangeParam != "7d" && rangeParam != "30d" {
		respondError(w, http.StatusBadRequest, "Invalid range. Must be 1d, 7d, or 30d")
		return
	}

	appID := r.URL.Query().Get("app_id")

	var query, timeFormat string
	var days int

	switch rangeParam {
	case "1d":
		days, timeFormat = 1, "2006-01-02T15:00:00Z"
		query = `SELECT toStartOfHour(ts) as time_bucket,
				countIf(action='allow'), countIf(action='block'),
				countIf(action='block' AND reason LIKE 'owasp_crs_rule:%'),
				countIf(action='block' AND reason LIKE 'bot_score:%'),
				countIf(action='challenge')
			FROM waf_events WHERE ts >= now()-toIntervalDay(1)`
	case "7d":
		days, timeFormat = 7, "2006-01-02"
		query = `SELECT toDate(ts) as time_bucket,
				countIf(action='allow'), countIf(action='block'),
				countIf(action='block' AND reason LIKE 'owasp_crs_rule:%'),
				countIf(action='block' AND reason LIKE 'bot_score:%'),
				countIf(action='challenge')
			FROM waf_events WHERE ts >= now()-toIntervalDay(7)`
	case "30d":
		days, timeFormat = 30, "2006-01-02"
		query = `SELECT toDate(ts) as time_bucket,
				countIf(action='allow'), countIf(action='block'),
				countIf(action='block' AND reason LIKE 'owasp_crs_rule:%'),
				countIf(action='block' AND reason LIKE 'bot_score:%'),
				countIf(action='challenge')
			FROM waf_events WHERE ts >= now()-toIntervalDay(30)`
	}

	args := []interface{}{}
	if appID != "" {
		query += " AND app_id = ?"
		args = append(args, appID)
	}
	query += " GROUP BY time_bucket ORDER BY time_bucket ASC"

	rows, err := h.logger.Conn().Query(context.Background(), query, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query analytics: "+err.Error())
		return
	}
	defer rows.Close()

	dataMap := make(map[string]*TrafficDataPoint)
	var totalAllow, totalBlock, totalBlockWAF, totalBlockBot, totalChallenge uint64

	for rows.Next() {
		var bucket time.Time
		var allow, block, blockWAF, blockBot, challenge uint64
		if err := rows.Scan(&bucket, &allow, &block, &blockWAF, &blockBot, &challenge); err != nil {
			continue
		}
		key := bucket.Format(timeFormat)
		dataMap[key] = &TrafficDataPoint{
			Timestamp: bucket.Format(time.RFC3339),
			Label:     formatLabel(bucket, rangeParam),
			Allow:     allow,
			Block:     block,
			Challenge: challenge,
		}
		totalAllow += allow
		totalBlock += block
		totalBlockWAF += blockWAF
		totalBlockBot += blockBot
		totalChallenge += challenge
	}

	data := generateTimeBuckets(rangeParam, days, dataMap, timeFormat)

	response := TrafficAnalyticsResponse{Range: rangeParam, Data: data}
	response.Summary.Total = totalAllow + totalBlock + totalChallenge
	response.Summary.Allow = totalAllow
	response.Summary.Block = totalBlock
	response.Summary.BlockWAF = totalBlockWAF
	response.Summary.BlockBot = totalBlockBot
	response.Summary.Challenge = totalChallenge
	respondJSON(w, http.StatusOK, response)
}

func generateTimeBuckets(rangeParam string, days int, dataMap map[string]*TrafficDataPoint, timeFormat string) []TrafficDataPoint {
	var data []TrafficDataPoint
	now := time.Now()

	if rangeParam == "1d" {
		for i := 23; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * time.Hour)
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
			key := t.Format(timeFormat)
			if point, exists := dataMap[key]; exists {
				data = append(data, *point)
			} else {
				data = append(data, TrafficDataPoint{Timestamp: t.Format(time.RFC3339), Label: formatLabel(t, rangeParam)})
			}
		}
	} else {
		for i := days - 1; i >= 0; i-- {
			t := now.AddDate(0, 0, -i)
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
			key := t.Format(timeFormat)
			if point, exists := dataMap[key]; exists {
				data = append(data, *point)
			} else {
				data = append(data, TrafficDataPoint{Timestamp: t.Format(time.RFC3339), Label: formatLabel(t, rangeParam)})
			}
		}
	}
	return data
}

func formatLabel(t time.Time, rangeParam string) string {
	if rangeParam == "1d" {
		return t.Format("15:04")
	}
	monthNames := []string{"", "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"}
	return monthNames[t.Month()] + " " + t.Format("2")
}

type ThreatEntry struct {
	Category string `json:"category"`
	Count    uint64 `json:"count"`
}

func (h *AnalyticsHandler) GetTopThreats(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)

	appIDThreats := r.URL.Query().Get("app_id")
	if appIDThreats != "" {
		where += " AND app_id = '" + sanitizeAppID(appIDThreats) + "'"
	}

	query := `SELECT reason
		FROM waf_events
		WHERE ` + where + `
			AND action IN ('block', 'challenge')
			AND reason != ''
		LIMIT 10000
	`

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query threats")
		return
	}
	defer rows.Close()

	categoryCount := make(map[string]uint64)

	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			continue
		}

		segments := splitReason(reason)
		bestCategory := ""
		bestScore := -1

		for _, seg := range segments {
			name, hasScore := parseReasonSegment(seg)
			if name == "" || name == "total" || name == "scoring_engine" {
				continue
			}
			normalized := normalizeCategory(name)
			if normalized == "" {
				continue
			}

			score := 0
			if hasScore {
				score = extractSegmentScore(seg)
			}

			if score > bestScore || (score == bestScore && bestCategory == "") {
				bestScore = score
				bestCategory = normalized
			}
		}

		if bestCategory != "" {
			categoryCount[bestCategory]++
		}
	}

	threats := make([]ThreatEntry, 0, len(categoryCount))
	for cat, cnt := range categoryCount {
		threats = append(threats, ThreatEntry{Category: cat, Count: cnt})
	}
	sortThreats(threats)

	respondJSON(w, http.StatusOK, threats)
}

func splitReason(reason string) []string {
	result := make([]string, 0, 8)
	start := 0
	for i := 0; i < len(reason); i++ {
		if reason[i] == '|' {
			if i > start {
				result = append(result, reason[start:i])
			}
			start = i + 1
		}
	}
	if start < len(reason) {
		result = append(result, reason[start:])
	}
	return result
}

func parseReasonSegment(seg string) (string, bool) {
	// Find last colon
	lastColon := -1
	for i := len(seg) - 1; i >= 0; i-- {
		if seg[i] == ':' {
			lastColon = i
			break
		}
	}
	if lastColon <= 0 {
		return seg, false
	}
	after := seg[lastColon+1:]
	// Check if after colon is a number (possibly negative)
	if len(after) == 0 {
		return seg, false
	}
	start := 0
	if after[0] == '-' {
		start = 1
	}
	if start >= len(after) {
		return seg, false
	}
	for i := start; i < len(after); i++ {
		if after[i] < '0' || after[i] > '9' {
			return seg, false
		}
	}
	return seg[:lastColon], true
}

// dominantCategoryFromReason finds the category with the highest score in a reason string.
// Returns the normalized dominant category (e.g. "bot_detection", "waf_rule").
func dominantCategoryFromReason(reason string) string {
	segments := splitReason(reason)
	bestCategory := ""
	bestScore := -1

	for _, seg := range segments {
		name, hasScore := parseReasonSegment(seg)
		if name == "" || name == "total" || name == "scoring_engine" {
			continue
		}
		normalized := normalizeCategory(name)
		if normalized == "" {
			continue
		}

		score := 0
		if hasScore {
			score = extractSegmentScore(seg)
		}

		if score > bestScore || (score == bestScore && bestCategory == "") {
			bestScore = score
			bestCategory = normalized
		}
	}
	return bestCategory
}

// extractSegmentScore returns the numeric score from a reason segment like "bot_detection:39".
func extractSegmentScore(seg string) int {
	lastColon := -1
	for i := len(seg) - 1; i >= 0; i-- {
		if seg[i] == ':' {
			lastColon = i
			break
		}
	}
	if lastColon < 0 || lastColon >= len(seg)-1 {
		return 0
	}
	after := seg[lastColon+1:]
	negative := false
	start := 0
	if after[0] == '-' {
		negative = true
		start = 1
	}
	if start >= len(after) {
		return 0
	}
	val := 0
	for i := start; i < len(after); i++ {
		if after[i] < '0' || after[i] > '9' {
			return 0
		}
		val = val*10 + int(after[i]-'0')
	}
	if negative {
		val = -val
	}
	return val
}

func normalizeCategory(name string) string {
	switch {
	case name == "bot_detection" || name == "bot_score" || name == "bot_composite":
		return "bot_detection"
	case name == "waf_anomaly" || len(name) > 8 && name[:8] == "owasp_crs":
		return "waf_rule"
	case name == "ip_reputation" || name == "datacenter_asn" || name == "cloud_provider":
		return "ip_reputation"
	case name == "protocol_anomaly":
		return "protocol_anomaly"
	case name == "rate_limit" || (len(name) > 10 && name[:10] == "rate_limit"):
		return "rate_limit"
	case len(name) >= 4 && name[:4] == "rule":
		return "custom_rule"
	case len(name) >= 14 && name[:14] == "ip_access_rule":
		return "ip_access"
	default:
		return ""
	}
}

func sortThreats(threats []ThreatEntry) {
	for i := 0; i < len(threats); i++ {
		for j := i + 1; j < len(threats); j++ {
			if threats[j].Count > threats[i].Count {
				threats[i], threats[j] = threats[j], threats[i]
			}
		}
	}
}

type DashboardInsightsResponse struct {
	TopIPs       []IPInsight       `json:"top_ips"`
	TopHosts     []HostInsight     `json:"top_hosts"`
	TopCountries []CountryInsight  `json:"top_countries"`
	TopProviders []ProviderInsight `json:"top_providers"`
	DeviceTypes  []DeviceInsight   `json:"device_types"`
	OSTypes      []OSInsight       `json:"os_types"`
}

type IPInsight struct {
	IP    string `json:"ip"`
	Count uint64 `json:"count"`
}

type HostInsight struct {
	Host  string `json:"host"`
	Count uint64 `json:"count"`
}

type CountryInsight struct {
	Country   string  `json:"country"`
	Total     uint64  `json:"total"`
	Blocked   uint64  `json:"blocked"`
	BlockRate float64 `json:"block_rate"`
}

type ProviderInsight struct {
	Provider   string  `json:"provider"`
	Total      uint64  `json:"total"`
	Blocked    uint64  `json:"blocked"`
	Challenged uint64  `json:"challenged"`
	BlockRate  float64 `json:"block_rate"`
	ThreatRate float64 `json:"threat_rate"`
}

type DeviceInsight struct {
	Device string `json:"device"`
	Count  uint64 `json:"count"`
}

type OSInsight struct {
	OS    string `json:"os"`
	Count uint64 `json:"count"`
}

func (h *AnalyticsHandler) GetDashboardInsights(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)

	appIDInsights := r.URL.Query().Get("app_id")
	if appIDInsights != "" {
		where += " AND app_id = '" + sanitizeAppID(appIDInsights) + "'"
	}

	ctx := context.Background()
	conn := h.logger.Conn()

	resp := DashboardInsightsResponse{}
	var wg sync.WaitGroup

	wg.Add(6)

	go func() {
		defer wg.Done()
		ipQuery := `SELECT ip, count() as cnt FROM waf_events
			WHERE ` + where + `
			AND action IN ('block', 'challenge')
			AND action NOT IN ('challenge_solved', 'challenge_failed')
			GROUP BY ip ORDER BY cnt DESC LIMIT 20`
		rows, err := conn.Query(ctx, ipQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var ip string
			var cnt uint64
			if rows.Scan(&ip, &cnt) == nil {
				resp.TopIPs = append(resp.TopIPs, IPInsight{IP: ip, Count: cnt})
			}
		}
	}()

	go func() {
		defer wg.Done()
		hostQuery := `SELECT host, count() as cnt FROM waf_events
			WHERE ` + where + `
			AND action IN ('block', 'challenge')
			AND action NOT IN ('challenge_solved', 'challenge_failed')
			GROUP BY host ORDER BY cnt DESC LIMIT 20`
		rows, err := conn.Query(ctx, hostQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var host string
			var cnt uint64
			if rows.Scan(&host, &cnt) == nil {
				resp.TopHosts = append(resp.TopHosts, HostInsight{Host: host, Count: cnt})
			}
		}
	}()

	go func() {
		defer wg.Done()
		countryQuery := `SELECT country, count() as total, countIf(action='block') as blocked
			FROM waf_events
			WHERE ` + where + ` AND country != ''
			GROUP BY country ORDER BY total DESC LIMIT 15`
		rows, err := conn.Query(ctx, countryQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var country string
			var total, blocked uint64
			if rows.Scan(&country, &total, &blocked) == nil {
				rate := float64(0)
				if total > 0 {
					rate = float64(blocked) / float64(total) * 100
				}
				resp.TopCountries = append(resp.TopCountries, CountryInsight{
					Country: country, Total: total, Blocked: blocked, BlockRate: rate,
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		providerQuery := `SELECT asn_org, count() as total, countIf(action='block') as blocked, countIf(action='challenge') as challenged
			FROM waf_events
			WHERE ` + where + ` AND asn_org != ''
			GROUP BY asn_org ORDER BY total DESC LIMIT 15`
		rows, err := conn.Query(ctx, providerQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var provider string
			var total, blocked, challenged uint64
			if rows.Scan(&provider, &total, &blocked, &challenged) == nil {
				blockRate := float64(0)
				threatRate := float64(0)
				if total > 0 {
					blockRate = float64(blocked) / float64(total) * 100
					threatRate = float64(blocked+challenged) / float64(total) * 100
				}
				resp.TopProviders = append(resp.TopProviders, ProviderInsight{
					Provider: provider, Total: total, Blocked: blocked, Challenged: challenged,
					BlockRate: blockRate, ThreatRate: threatRate,
				})
			}
		}
	}()

	go func() {
		defer wg.Done()
		deviceQuery := `SELECT device_type, count() as cnt FROM waf_events
			WHERE ` + where + ` AND device_type != ''
			GROUP BY device_type ORDER BY cnt DESC`
		rows, err := conn.Query(ctx, deviceQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var device string
			var cnt uint64
			if rows.Scan(&device, &cnt) == nil {
				resp.DeviceTypes = append(resp.DeviceTypes, DeviceInsight{Device: device, Count: cnt})
			}
		}
	}()

	go func() {
		defer wg.Done()
		osQuery := `SELECT os, count() as cnt FROM waf_events
			WHERE ` + where + ` AND os != ''
			GROUP BY os ORDER BY cnt DESC`
		rows, err := conn.Query(ctx, osQuery)
		if err != nil {
			return
		}
		defer rows.Close()
		for rows.Next() {
			var os string
			var cnt uint64
			if rows.Scan(&os, &cnt) == nil {
				resp.OSTypes = append(resp.OSTypes, OSInsight{OS: os, Count: cnt})
			}
		}
	}()

	wg.Wait()

	if resp.TopIPs == nil {
		resp.TopIPs = []IPInsight{}
	}
	if resp.TopHosts == nil {
		resp.TopHosts = []HostInsight{}
	}
	if resp.TopCountries == nil {
		resp.TopCountries = []CountryInsight{}
	}
	if resp.TopProviders == nil {
		resp.TopProviders = []ProviderInsight{}
	}
	if resp.DeviceTypes == nil {
		resp.DeviceTypes = []DeviceInsight{}
	}
	if resp.OSTypes == nil {
		resp.OSTypes = []OSInsight{}
	}

	respondJSON(w, http.StatusOK, resp)
}

type ChallengeStatsResponse struct {
	Total  uint64  `json:"total"`
	Solved uint64  `json:"solved"`
	Failed uint64  `json:"failed"`
	Issued uint64  `json:"issued"`
	Rate   float64 `json:"rate"`
}

func (h *AnalyticsHandler) GetChallengeStats(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if rangeParam != "1d" && rangeParam != "7d" && rangeParam != "30d" {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	var interval string
	switch rangeParam {
	case "1d":
		interval = "1"
	case "7d":
		interval = "7"
	case "30d":
		interval = "30"
	}

	query := `SELECT
		countIf(action IN ('challenge', 'challenge_solved', 'challenge_failed')) as total,
		countIf(action = 'challenge_solved') as solved,
		countIf(action = 'challenge_failed') as failed,
		countIf(action = 'challenge') as issued
		FROM waf_events
		WHERE ts >= now() - toIntervalDay(` + interval + `)`

	var total, solved, failed, issued uint64
	row := h.logger.Conn().QueryRow(context.Background(), query)
	if err := row.Scan(&total, &solved, &failed, &issued); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query challenge stats")
		return
	}

	rate := float64(0)
	if total > 0 {
		rate = float64(solved) / float64(total) * 100
	}

	respondJSON(w, http.StatusOK, ChallengeStatsResponse{
		Total: total, Solved: solved, Failed: failed, Issued: issued, Rate: rate,
	})
}

type TopBlockedBotsResponse struct {
	UA    string `json:"ua"`
	Count uint64 `json:"count"`
}

func (h *AnalyticsHandler) GetTopBlockedBots(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		rangeParam = "7d"
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)

	query := `SELECT ua, count() as cnt FROM waf_events
		WHERE ` + where + `
		AND action = 'block'
		AND reason LIKE '%bot%'
		AND ua != ''
		GROUP BY ua ORDER BY cnt DESC LIMIT 20`

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query blocked bots")
		return
	}
	defer rows.Close()

	var bots []TopBlockedBotsResponse
	for rows.Next() {
		var ua string
		var cnt uint64
		if rows.Scan(&ua, &cnt) == nil {
			bots = append(bots, TopBlockedBotsResponse{UA: ua, Count: cnt})
		}
	}

	if bots == nil {
		bots = []TopBlockedBotsResponse{}
	}

	respondJSON(w, http.StatusOK, bots)
}

type WAFStatsResponse struct {
	Blocked    uint64 `json:"blocked"`
	Challenged uint64 `json:"challenged"`
}

func (h *AnalyticsHandler) GetWAFStats(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}

	var interval string
	switch rangeParam {
	case "1d":
		interval = "1"
	case "7d":
		interval = "7"
	case "30d":
		interval = "30"
	default:
		interval = "7"
	}

	query := `SELECT
		countIf(action = 'block' AND reason LIKE '%waf%') as blocked,
		countIf(action = 'challenge' AND reason LIKE '%waf%') as challenged
		FROM waf_events
		WHERE ts >= now() - toIntervalDay(` + interval + `)`

	var blocked, challenged uint64
	row := h.logger.Conn().QueryRow(context.Background(), query)
	if err := row.Scan(&blocked, &challenged); err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query WAF stats")
		return
	}

	respondJSON(w, http.StatusOK, WAFStatsResponse{Blocked: blocked, Challenged: challenged})
}

type ThreatIPEntry struct {
	IP        string  `json:"ip"`
	Country   string  `json:"country"`
	ASNOrg    string  `json:"asn_org"`
	Total     uint64  `json:"total"`
	Blocked   uint64  `json:"blocked"`
	Challenged uint64 `json:"challenged"`
	BlockRate  float64 `json:"block_rate"`
}

type ThreatIPResponse struct {
	Items      []ThreatIPEntry `json:"items"`
	TotalIPs   uint64          `json:"total_ips"`
	TotalEvents uint64         `json:"total_events"`
}

func (h *AnalyticsHandler) GetThreatIPs(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)
	appID := r.URL.Query().Get("app_id")
	if appID != "" {
		where += " AND app_id = '" + sanitizeAppID(appID) + "'"
	}

	query := `SELECT
		ip,
		any(country) as country,
		any(asn_org) as asn_org,
		count() as total,
		countIf(action = 'block') as blocked,
		countIf(action = 'challenge') as challenged
	FROM waf_events
	WHERE ` + where + `
		AND action IN ('block', 'challenge')
	GROUP BY ip
	ORDER BY total DESC
	LIMIT 50`

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query threat IPs")
		return
	}
	defer rows.Close()

	var items []ThreatIPEntry
	var totalEvents uint64

	for rows.Next() {
		var entry ThreatIPEntry
		if err := rows.Scan(&entry.IP, &entry.Country, &entry.ASNOrg, &entry.Total, &entry.Blocked, &entry.Challenged); err != nil {
			continue
		}
		if entry.Total > 0 {
			entry.BlockRate = float64(entry.Blocked) / float64(entry.Total) * 100
		}
		items = append(items, entry)
		totalEvents += entry.Total
	}

	if items == nil {
		items = []ThreatIPEntry{}
	}

	respondJSON(w, http.StatusOK, ThreatIPResponse{
		Items:       items,
		TotalIPs:    uint64(len(items)),
		TotalEvents: totalEvents,
	})
}

type WAFRuleEntry struct {
	RuleID     string `json:"rule_id"`
	Total      uint64 `json:"total"`
	Blocked    uint64 `json:"blocked"`
	Challenged uint64 `json:"challenged"`
	Allowed    uint64 `json:"allowed"`
}

type WAFRuleIntelResponse struct {
	Items []WAFRuleEntry `json:"items"`
}

func (h *AnalyticsHandler) GetWAFRuleIntel(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)

	appID := r.URL.Query().Get("app_id")
	if appID != "" {
		where += " AND app_id = '" + sanitizeAppID(appID) + "'"
	}

	query := `SELECT pipeline_trace, action
	FROM waf_events
	WHERE ` + where + `
		AND pipeline_trace != ''
		AND pipeline_trace LIKE '%waf_anomaly","score":%'
	LIMIT 20000`

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query WAF rule intel")
		return
	}
	defer rows.Close()

	type ruleStat struct {
		Total      uint64
		Blocked    uint64
		Challenged uint64
		Allowed    uint64
	}
	ruleMap := make(map[string]*ruleStat)

	for rows.Next() {
		var traceStr, action string
		if err := rows.Scan(&traceStr, &action); err != nil {
			continue
		}

		ruleIDs := extractRuleIDsFromTrace(traceStr)
		for _, ruleID := range ruleIDs {
			if ruleMap[ruleID] == nil {
				ruleMap[ruleID] = &ruleStat{}
			}
			st := ruleMap[ruleID]
			st.Total++
			switch action {
			case "block":
				st.Blocked++
			case "challenge":
				st.Challenged++
			default:
				st.Allowed++
			}
		}
	}

	items := make([]WAFRuleEntry, 0, len(ruleMap))
	for ruleID, st := range ruleMap {
		items = append(items, WAFRuleEntry{
			RuleID:     ruleID,
			Total:      st.Total,
			Blocked:    st.Blocked,
			Challenged: st.Challenged,
			Allowed:    st.Allowed,
		})
	}

	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Total > items[i].Total {
				items[i], items[j] = items[j], items[i]
			}
		}
	}

	if len(items) > 20 {
		items = items[:20]
	}
	if items == nil {
		items = []WAFRuleEntry{}
	}

	respondJSON(w, http.StatusOK, WAFRuleIntelResponse{Items: items})
}

// extractRuleIDsFromTrace parses pipeline_trace JSON and collects all
// non-empty rule_id values from waf_anomaly stages.
// Handles comma-separated rule IDs (e.g. "942100,920280").
func extractRuleIDsFromTrace(traceStr string) []string {
	const ruleIDKey = `"rule_id":"`
	var ids []string
	search := traceStr
	for {
		pos := indexString(search, ruleIDKey)
		if pos < 0 {
			break
		}
		start := pos + len(ruleIDKey)
		end := start
		for end < len(search) && search[end] != '"' {
			end++
		}
		if end > start {
			ruleID := search[start:end]
			if ruleID != "" {
				// Split comma-separated rule IDs
				for _, id := range strings.Split(ruleID, ",") {
					id = strings.TrimSpace(id)
					if id != "" {
						ids = append(ids, id)
					}
				}
			}
		}
		if end >= len(search) {
			break
		}
		search = search[end+1:]
	}
	return ids
}

type ScoreBucket struct {
	Range string `json:"range"`
	Count uint64 `json:"count"`
}

type CategoryTrend struct {
	Label         string `json:"label"`
	IPReputation  uint64 `json:"ip_reputation"`
	BotDetection  uint64 `json:"bot_detection"`
	WAFAnomaly    uint64 `json:"waf_anomaly"`
	ProtocolAnomaly uint64 `json:"protocol_anomaly"`
}

type CategoryAverage struct {
	IPReputation    float64 `json:"ip_reputation"`
	BotDetection    float64 `json:"bot_detection"`
	WAFAnomaly      float64 `json:"waf_anomaly"`
	ProtocolAnomaly float64 `json:"protocol_anomaly"`
}

type ThreatSummaryResponse struct {
	ScoreDistribution []ScoreBucket   `json:"score_distribution"`
	CategoryTrend     []CategoryTrend `json:"category_trend"`
	CategoryAvg       CategoryAverage `json:"category_avg"`
}

func (h *AnalyticsHandler) GetThreatSummary(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, bucketFn, bucketCount := rangeToWhereClause(rangeParam)

	appID := r.URL.Query().Get("app_id")
	if appID != "" {
		where += " AND app_id = '" + sanitizeAppID(appID) + "'"
	}

	buckets := []ScoreBucket{
		{Range: "0–19"},
		{Range: "20–39"},
		{Range: "40–49"},
		{Range: "50–59"},
		{Range: "60–79"},
		{Range: "80–100"},
	}

	scoreQuery := `SELECT pipeline_trace
	FROM waf_events
	WHERE ` + where + `
		AND pipeline_trace != ''
		AND action IN ('block', 'challenge', 'allow')
	LIMIT 10000`

	scoreRows, err := h.logger.Conn().Query(context.Background(), scoreQuery)
	if err == nil {
		defer scoreRows.Close()
		for scoreRows.Next() {
			var traceStr string
			if err := scoreRows.Scan(&traceStr); err != nil {
				continue
			}
			score := extractScoreFromTrace(traceStr)
			if score < 0 {
				continue
			}
			switch {
			case score <= 19:
				buckets[0].Count++
			case score <= 39:
				buckets[1].Count++
			case score <= 49:
				buckets[2].Count++
			case score <= 59:
				buckets[3].Count++
			case score <= 79:
				buckets[4].Count++
			default:
				buckets[5].Count++
			}
		}
	}

	trendQuery := `SELECT ` + bucketFn + ` as t, reason
	FROM waf_events
	WHERE ` + where + `
		AND action IN ('block', 'challenge')
		AND reason != ''
	LIMIT 20000`

	isMinuteBucket := rangeParam == "5min" || rangeParam == "15min" || rangeParam == "1h"
	var timeFormat string
	if isMinuteBucket {
		timeFormat = "2006-01-02T15:04:00Z"
	} else if rangeParam == "1d" {
		timeFormat = "2006-01-02T15:00:00Z"
	} else {
		timeFormat = "2006-01-02"
	}

	trendMap := make(map[string]*CategoryTrend)

	// Accumulators for category score totals.
	var totalScoreIPRep, totalScoreBot, totalScoreWAF, totalScoreProto int64

	trendRows, err := h.logger.Conn().Query(context.Background(), trendQuery)
	if err == nil {
		defer trendRows.Close()
		for trendRows.Next() {
			var t time.Time
			var reason string
			if err := trendRows.Scan(&t, &reason); err != nil {
				continue
			}
			key := t.Format(timeFormat)
			if trendMap[key] == nil {
				trendMap[key] = &CategoryTrend{Label: formatLabelForRange(t, rangeParam)}
			}

			// Count all categories present in this event and accumulate scores.
			segments := splitReason(reason)
			seen := make(map[string]bool)
			for _, seg := range segments {
				name, hasScore := parseReasonSegment(seg)
				if name == "" || name == "total" || name == "scoring_engine" {
					continue
				}
				normalized := normalizeCategory(name)
				if normalized == "" || seen[normalized] {
					continue
				}
				seen[normalized] = true

				score := 0
				if hasScore {
					score = extractSegmentScore(seg)
				}

				switch normalized {
				case "ip_reputation":
					trendMap[key].IPReputation++
					totalScoreIPRep += int64(score)
				case "bot_detection":
					trendMap[key].BotDetection++
					totalScoreBot += int64(score)
				case "waf_rule":
					trendMap[key].WAFAnomaly++
					totalScoreWAF += int64(score)
				case "protocol_anomaly":
					trendMap[key].ProtocolAnomaly++
					totalScoreProto += int64(score)
				}
			}
		}
	}

	trend := generateCategoryTrendBuckets(rangeParam, bucketCount, trendMap, timeFormat, isMinuteBucket)

	var avg CategoryAverage
	totalAvg := float64(totalScoreIPRep) + float64(totalScoreBot) + float64(totalScoreWAF) + float64(totalScoreProto)
	if totalAvg > 0 {
		avg.IPReputation = float64(totalScoreIPRep) / totalAvg * 100
		avg.BotDetection = float64(totalScoreBot) / totalAvg * 100
		avg.WAFAnomaly = float64(totalScoreWAF) / totalAvg * 100
		avg.ProtocolAnomaly = float64(totalScoreProto) / totalAvg * 100
	}

	respondJSON(w, http.StatusOK, ThreatSummaryResponse{
		ScoreDistribution: buckets,
		CategoryTrend:     trend,
		CategoryAvg:       avg,
	})
}

func extractScoreFromTrace(traceStr string) int {
	const scoreKey = `"score":`
	idx := 0
	for idx < len(traceStr) {
		pos := indexString(traceStr[idx:], scoreKey)
		if pos < 0 {
			break
		}
		pos += idx + len(scoreKey)
		if pos >= len(traceStr) {
			break
		}
		negative := false
		if traceStr[pos] == '-' {
			negative = true
			pos++
		}
		end := pos
		for end < len(traceStr) && traceStr[end] >= '0' && traceStr[end] <= '9' {
			end++
		}
		if end > pos {
			val := 0
			for i := pos; i < end; i++ {
				val = val*10 + int(traceStr[i]-'0')
			}
			if negative {
				val = -val
			}
			if val >= 0 {
				return val
			}
		}
		idx = pos
	}
	return -1
}

func indexString(s, sub string) int {
	if len(sub) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func generateCategoryTrendBuckets(rangeParam string, bucketCount int, dataMap map[string]*CategoryTrend, timeFormat string, isMinute bool) []CategoryTrend {
	var data []CategoryTrend
	now := time.Now()

	if isMinute {
		// minute-level buckets
		for i := bucketCount - 1; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * time.Minute)
			t = t.Truncate(time.Minute)
			key := t.Format(timeFormat)
			if p, ok := dataMap[key]; ok {
				data = append(data, *p)
			} else {
				data = append(data, CategoryTrend{Label: formatLabelForRange(t, rangeParam)})
			}
		}
	} else if rangeParam == "1d" {
		for i := bucketCount - 1; i >= 0; i-- {
			t := now.Add(-time.Duration(i) * time.Hour)
			t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), 0, 0, 0, t.Location())
			key := t.Format(timeFormat)
			if p, ok := dataMap[key]; ok {
				data = append(data, *p)
			} else {
				data = append(data, CategoryTrend{Label: formatLabelForRange(t, rangeParam)})
			}
		}
	} else {
		for i := bucketCount - 1; i >= 0; i-- {
			t := now.AddDate(0, 0, -i)
			t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, t.Location())
			key := t.Format(timeFormat)
			if p, ok := dataMap[key]; ok {
				data = append(data, *p)
			} else {
				data = append(data, CategoryTrend{Label: formatLabelForRange(t, rangeParam)})
			}
		}
	}
	return data
}

type CustomRuleEntry struct {
	RuleID     string `json:"rule_id"`
	RuleName   string `json:"rule_name"`
	Total      uint64 `json:"total"`
	Blocked    uint64 `json:"blocked"`
	Challenged uint64 `json:"challenged"`
	Allowed    uint64 `json:"allowed"`
}

type CustomRuleIntelResponse struct {
	Items []CustomRuleEntry `json:"items"`
}

func (h *AnalyticsHandler) GetCustomRuleIntel(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	rangeParam := r.URL.Query().Get("range")
	if rangeParam == "" {
		rangeParam = "7d"
	}
	if !validateRange(rangeParam) {
		respondError(w, http.StatusBadRequest, "Invalid range")
		return
	}

	where, _, _, _ := rangeToWhereClause(rangeParam)
	appID := r.URL.Query().Get("app_id")
	if appID != "" {
		where += " AND app_id = '" + sanitizeAppID(appID) + "'"
	}

	// Fetch all reasons that contain a custom rule match.
	// Format: rule:ID:Name (e.g. rule:5:managed)
	query := `SELECT reason, action
	FROM waf_events
	WHERE ` + where + `
		AND reason LIKE '%rule:%'
		AND reason != ''
	LIMIT 20000`

	rows, err := h.logger.Conn().Query(context.Background(), query)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query custom rule intel")
		return
	}
	defer rows.Close()

	type ruleStat struct {
		Name       string
		Total      uint64
		Blocked    uint64
		Challenged uint64
		Allowed    uint64
	}
	ruleMap := make(map[string]*ruleStat)

	for rows.Next() {
		var reason, action string
		if err := rows.Scan(&reason, &action); err != nil {
			continue
		}

		// reason may be a pipe-separated string; find the rule:ID:Name segment
		segments := splitReason(reason)
		for _, seg := range segments {
			ruleID, ruleName := parseCustomRuleSegment(seg)
			if ruleID == "" {
				continue
			}
			if ruleMap[ruleID] == nil {
				ruleMap[ruleID] = &ruleStat{Name: ruleName}
			} else if ruleMap[ruleID].Name == "" && ruleName != "" {
				ruleMap[ruleID].Name = ruleName
			}
			st := ruleMap[ruleID]
			st.Total++
			switch action {
			case "block":
				st.Blocked++
			case "challenge":
				st.Challenged++
			default:
				st.Allowed++
			}
		}
	}

	items := make([]CustomRuleEntry, 0, len(ruleMap))
	for ruleID, st := range ruleMap {
		items = append(items, CustomRuleEntry{
			RuleID:     ruleID,
			RuleName:   st.Name,
			Total:      st.Total,
			Blocked:    st.Blocked,
			Challenged: st.Challenged,
			Allowed:    st.Allowed,
		})
	}

	// Sort by total desc
	for i := 0; i < len(items); i++ {
		for j := i + 1; j < len(items); j++ {
			if items[j].Total > items[i].Total {
				items[i], items[j] = items[j], items[i]
			}
		}
	}
	if len(items) > 20 {
		items = items[:20]
	}
	if items == nil {
		items = []CustomRuleEntry{}
	}

	respondJSON(w, http.StatusOK, CustomRuleIntelResponse{Items: items})
}

// parseCustomRuleSegment parses "rule:5:managed" → ("5", "managed")
// or "rule:5" → ("5", "")
// Ignores segments like "owasp_crs_rule:" or "custom_rule"
func parseCustomRuleSegment(seg string) (id, name string) {
	if len(seg) < 6 || seg[:5] != "rule:" {
		return "", ""
	}
	// skip "owasp_crs_rule:" or "ip_access_rule:" etc.
	for i := 5; i < len(seg); i++ {
		if seg[i] == ':' {
			break
		}
		if seg[i] < '0' || seg[i] > '9' {
			return "", ""
		}
	}
	rest := seg[5:]
	colonIdx := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == ':' {
			colonIdx = i
			break
		}
	}
	if colonIdx < 0 {
		return rest, ""
	}
	return rest[:colonIdx], rest[colonIdx+1:]
}
