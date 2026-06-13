package handler

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/vibeswaf/waf/internal/logger"
)


type LogHandler struct {
	logger *logger.Clickhouse
}


func NewLogHandler(logger *logger.Clickhouse) *LogHandler {
	return &LogHandler{
		logger: logger,
	}
}


func (h *LogHandler) ListLogs(w http.ResponseWriter, r *http.Request) {
	if h.logger == nil || h.logger.Conn() == nil {
		respondError(w, http.StatusServiceUnavailable, "ClickHouse not available")
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 10000 {
			limit = l
		}
	}

	action := r.URL.Query().Get("action")
	appID := r.URL.Query().Get("app_id")
	search := r.URL.Query().Get("q")
	reasonLike := r.URL.Query().Get("reason_like")
	traceLike := r.URL.Query().Get("trace_like")

	daysStr := r.URL.Query().Get("days")
	days := 0
	if daysStr != "" {
		if d, err := strconv.Atoi(daysStr); err == nil && d > 0 && d <= 90 {
			days = d
		}
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if offsetStr != "" {
		if o, err := strconv.Atoi(offsetStr); err == nil && o >= 0 && o <= 10000 {
			offset = o
		}
	}

	query := "SELECT ts, ip, host, path, ua, action, reason, status, latency, pipeline_latency, upstream_latency, app_id, country, asn, asn_org, device_type, os, pipeline_trace FROM waf_events WHERE 1=1"
	args := []interface{}{}

	if days > 0 {
		query += " AND ts >= now() - toIntervalDay(" + strconv.Itoa(days) + ")"
	}

	if action != "" {
		query += " AND action = ?"
		args = append(args, action)
	}

	if appID != "" {
		query += " AND app_id = ?"
		args = append(args, appID)
	}

	if reasonLike != "" {
		query += " AND reason LIKE ?"
		args = append(args, "%"+reasonLike+"%")
	}

	if traceLike != "" {
		query += " AND pipeline_trace LIKE ?"
		args = append(args, "%"+traceLike+"%")
	}

	if search != "" {
		s := "%" + strings.ToLower(search) + "%"
		query += " AND (ip LIKE ? OR lower(host) LIKE ? OR lower(path) LIKE ? OR lower(ua) LIKE ? OR lower(reason) LIKE ? OR lower(country) LIKE ? OR lower(app_id) LIKE ? OR lower(asn_org) LIKE ?)"
		args = append(args, s, s, s, s, s, s, s, s)
	}

	query += " ORDER BY ts DESC LIMIT " + strconv.Itoa(limit) + " OFFSET " + strconv.Itoa(offset)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	rows, err := h.logger.Conn().Query(ctx, query, args...)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "Failed to query logs: "+err.Error())
		return
	}
	defer rows.Close()

	logs := make([]map[string]interface{}, 0)
	for rows.Next() {
		var ts time.Time
		var ip, host, path, ua, action, reason, appID, country, asnOrg, deviceType, os, pipelineTrace string
		var status uint16
		var latency, pipelineLatency, upstreamLatency, asn uint32

		if err := rows.Scan(&ts, &ip, &host, &path, &ua, &action, &reason, &status, &latency, &pipelineLatency, &upstreamLatency, &appID, &country, &asn, &asnOrg, &deviceType, &os, &pipelineTrace); err != nil {
			continue
		}

		logs = append(logs, map[string]interface{}{
			"ts":               ts.Format(time.RFC3339),
			"ip":               ip,
			"host":             host,
			"path":             path,
			"ua":               ua,
			"action":           action,
			"reason":           reason,
			"status":           status,
			"latency":          latency,
			"pipeline_latency": pipelineLatency,
			"upstream_latency": upstreamLatency,
			"app_id":           appID,
			"country":          country,
			"asn":              asn,
			"asn_org":          asnOrg,
			"device_type":      deviceType,
			"os":               os,
			"pipeline_trace":   pipelineTrace,
		})
	}

	// Only run COUNT query when pagination is actually needed (offset > 0 or result is full)
	var totalCount uint64
	needsCount := offset > 0 || len(logs) >= limit

	if needsCount {
		countQuery := "SELECT COUNT(*) FROM waf_events WHERE 1=1"
		countArgs := []interface{}{}

		if days > 0 {
			countQuery += " AND ts >= now() - toIntervalDay(" + strconv.Itoa(days) + ")"
		}
		if action != "" {
			countQuery += " AND action = ?"
			countArgs = append(countArgs, action)
		}
		if appID != "" {
			countQuery += " AND app_id = ?"
			countArgs = append(countArgs, appID)
		}
		if reasonLike != "" {
			countQuery += " AND reason LIKE ?"
			countArgs = append(countArgs, "%"+reasonLike+"%")
		}
		if search != "" {
			s := "%" + strings.ToLower(search) + "%"
			countQuery += " AND (ip LIKE ? OR lower(host) LIKE ? OR lower(path) LIKE ? OR lower(ua) LIKE ? OR lower(reason) LIKE ? OR lower(country) LIKE ? OR lower(app_id) LIKE ? OR lower(asn_org) LIKE ?)"
			countArgs = append(countArgs, s, s, s, s, s, s, s, s)
		}

		_ = h.logger.Conn().QueryRow(ctx, countQuery, countArgs...).Scan(&totalCount)
	} else {
		totalCount = uint64(len(logs))
	}

	response := map[string]interface{}{
		"data":  logs,
		"total": totalCount,
	}
	respondJSON(w, http.StatusOK, response)
}
