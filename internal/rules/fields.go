package rules

import (
	"strings"

	"github.com/vibeswaf/waf/internal/pipeline"
)


type FieldType int

const (
	FieldTypeString FieldType = iota
	FieldTypeInt
	FieldTypeBool
	FieldTypeIP
)


type FieldDef struct {
	Name        string
	Type        FieldType
	AllowedOps  []string
	Description string
	Extractor   func(*pipeline.Context) interface{}
}


var FieldRegistry = map[string]FieldDef{

	"ip.src": {
		Name:        "ip.src",
		Type:        FieldTypeIP,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "Source IP address",
		Extractor:   extractIPSrc,
	},
	"ip.version": {
		Name:        "ip.version",
		Type:        FieldTypeInt,
		AllowedOps:  []string{"eq", "neq"},
		Description: "IP version (4 or 6)",
		Extractor:   extractIPVersion,
	},
	"ip.is_datacenter": {
		Name:        "ip.is_datacenter",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is IP from datacenter",
		Extractor:   extractIsDatacenter,
	},


	"asn": {
		Name:        "asn",
		Type:        FieldTypeInt,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "Autonomous System Number",
		Extractor:   extractASN,
	},
	"country": {
		Name:        "country",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "Country code (ISO 3166-1 alpha-2)",
		Extractor:   extractCountry,
	},


	"http.host": {
		Name:        "http.host",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in", "contains", "not_contains", "prefix", "suffix", "regex", "not_regex"},
		Description: "Host header",
		Extractor:   extractHTTPHost,
	},
	"http.path": {
		Name:        "http.path",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in", "contains", "not_contains", "prefix", "suffix", "regex", "not_regex"},
		Description: "URL path",
		Extractor:   extractHTTPPath,
	},
	"http.query": {
		Name:        "http.query",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "contains", "not_contains", "regex", "not_regex", "exists", "not_exists"},
		Description: "Query string",
		Extractor:   extractHTTPQuery,
	},
	"http.scheme": {
		Name:        "http.scheme",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq"},
		Description: "http or https",
		Extractor:   extractHTTPScheme,
	},
	"http.version": {
		Name:        "http.version",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq"},
		Description: "HTTP version (1.0, 1.1, 2.0, 3.0)",
		Extractor:   extractHTTPVersion,
	},
	"http.method": {
		Name:        "http.method",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "HTTP method (GET, POST, etc)",
		Extractor:   extractHTTPMethod,
	},


	"http.ua": {
		Name:        "http.ua",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in", "contains", "not_contains", "regex", "not_regex", "exists", "not_exists"},
		Description: "User-Agent header",
		Extractor:   extractHTTPUA,
	},
	"http.cookie": {
		Name:        "http.cookie",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "contains", "not_contains", "exists", "not_exists"},
		Description: "Cookie header",
		Extractor:   extractHTTPCookie,
	},
	"http.referer": {
		Name:        "http.referer",
		Type:        FieldTypeString,
		AllowedOps:  []string{"contains", "not_contains", "prefix", "exists", "not_exists"},
		Description: "Referer header",
		Extractor:   extractHTTPReferer,
	},
	"http.accept": {
		Name:        "http.accept",
		Type:        FieldTypeString,
		AllowedOps:  []string{"contains", "not_contains", "exists", "not_exists"},
		Description: "Accept header",
		Extractor:   extractHTTPAccept,
	},


	"client.os": {
		Name:        "client.os",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "Operating system",
		Extractor:   extractClientOS,
	},
	"client.browser": {
		Name:        "client.browser",
		Type:        FieldTypeString,
		AllowedOps:  []string{"eq", "neq", "in", "not_in"},
		Description: "Browser name",
		Extractor:   extractClientBrowser,
	},
	"client.is_mobile": {
		Name:        "client.is_mobile",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is mobile device",
		Extractor:   extractClientIsMobile,
	},
	"client.is_desktop": {
		Name:        "client.is_desktop",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is desktop device",
		Extractor:   extractClientIsDesktop,
	},
	"client.is_tablet": {
		Name:        "client.is_tablet",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is tablet device",
		Extractor:   extractClientIsTablet,
	},
	"device.is_mobile": {
		Name:        "device.is_mobile",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is mobile device",
		Extractor:   extractClientIsMobile,
	},
	"device.is_desktop": {
		Name:        "device.is_desktop",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is desktop device",
		Extractor:   extractClientIsDesktop,
	},
	"device.is_tablet": {
		Name:        "device.is_tablet",
		Type:        FieldTypeBool,
		AllowedOps:  []string{"eq", "neq"},
		Description: "Is tablet device",
		Extractor:   extractClientIsTablet,
	},


	"req.rate": {
		Name:        "req.rate",
		Type:        FieldTypeInt,
		AllowedOps:  []string{"eq", "neq", "gt", "lt", "gte", "lte"},
		Description: "Request rate per minute",
		Extractor:   extractReqRate,
	},
}



func extractIPSrc(ctx *pipeline.Context) interface{} {
	return ctx.ClientIP
}

func extractIPVersion(ctx *pipeline.Context) interface{} {
	if strings.Contains(ctx.ClientIP, ":") {
		return 6
	}
	return 4
}

func extractIsDatacenter(ctx *pipeline.Context) interface{} {
	return ctx.IsDatacenter
}


func extractASN(ctx *pipeline.Context) interface{} {
	return int(ctx.ASN)
}

func extractCountry(ctx *pipeline.Context) interface{} {
	return strings.ToUpper(ctx.Country)
}

func extractHTTPHost(ctx *pipeline.Context) interface{} {
	return ctx.Normalized.Host
}

func extractHTTPPath(ctx *pipeline.Context) interface{} {
	return ctx.Normalized.Path
}

func extractHTTPQuery(ctx *pipeline.Context) interface{} {
	return ctx.Normalized.Query
}

func extractHTTPScheme(ctx *pipeline.Context) interface{} {
	if ctx.Request.TLS != nil {
		return "https"
	}
	return "http"
}

func extractHTTPVersion(ctx *pipeline.Context) interface{} {
	return ctx.Request.Proto
}

func extractHTTPMethod(ctx *pipeline.Context) interface{} {
	return ctx.Normalized.Method
}

func extractHTTPUA(ctx *pipeline.Context) interface{} {
	return ctx.Normalized.UA
}

func extractHTTPCookie(ctx *pipeline.Context) interface{} {
	return ctx.Request.Header.Get("Cookie")
}

func extractHTTPReferer(ctx *pipeline.Context) interface{} {
	return ctx.Request.Header.Get("Referer")
}

func extractHTTPAccept(ctx *pipeline.Context) interface{} {
	return ctx.Request.Header.Get("Accept")
}

func extractClientOS(ctx *pipeline.Context) interface{} {
	return ""
}

func extractClientBrowser(ctx *pipeline.Context) interface{} {
	return ""
}

func extractClientIsMobile(ctx *pipeline.Context) interface{} {
	ua := strings.ToLower(ctx.Normalized.UA)
	mobileKW := []string{"mobile", "android", "iphone", "ipod", "blackberry", "windows phone", "opera mini"}
	for _, kw := range mobileKW {
		if strings.Contains(ua, kw) && !strings.Contains(ua, "ipad") && !strings.Contains(ua, "tablet") {
			return true
		}
	}
	return false
}

func extractClientIsDesktop(ctx *pipeline.Context) interface{} {
	mobile, _ := extractClientIsMobile(ctx).(bool)
	tablet, _ := extractClientIsTablet(ctx).(bool)
	return !mobile && !tablet
}

func extractClientIsTablet(ctx *pipeline.Context) interface{} {
	ua := strings.ToLower(ctx.Normalized.UA)
	for _, kw := range []string{"ipad", "tablet", "kindle"} {
		if strings.Contains(ua, kw) {
			return true
		}
	}
	return false
}

func extractReqRate(ctx *pipeline.Context) interface{} {
	return 0
}
