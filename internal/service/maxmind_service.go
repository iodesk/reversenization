package service

import (
	"fmt"
	"net"

	"github.com/vibeswaf/waf/internal/config"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/oschwald/geoip2-golang"
	"github.com/oschwald/maxminddb-golang"
)


type MaxMindService struct {
	mu sync.RWMutex

	countryDB *geoip2.Reader
	asnDB *geoip2.Reader

	countryPath string
	asnPath string
	
	asnOrgMap map[uint]string
	datacenterASNs map[uint]bool
}


type GeoIPResult struct {
	Country string
	CountryCode string
	ASN uint
	ASNOrg string
	IsDatacenter bool
}


func NewMaxMindService(dbPath string) (*MaxMindService, error) {
	service := &MaxMindService{
		countryPath: filepath.Join(dbPath, "GeoLite2-Country.mmdb"),
		asnPath: filepath.Join(dbPath, "GeoLite2-ASN.mmdb"),
	}


	if err := service.loadDatabases(); err != nil {
		return nil, err
	}

	config.GetAppConfig().LogInfo("[MaxMind] Loaded databases from %s", dbPath)
	return service, nil
}


func (s *MaxMindService) loadDatabases() error {
	s.mu.Lock()
	defer s.mu.Unlock()


	if _, err := os.Stat(s.countryPath); err == nil {
		db, err := geoip2.Open(s.countryPath)
		if err != nil {
			return fmt.Errorf("failed to open country database: %w", err)
		}
		s.countryDB = db
	} else {
		config.GetAppConfig().LogWarn("[MaxMind] Country database not found: %s", s.countryPath)
	}

	if _, err := os.Stat(s.asnPath); err == nil {
		db, err := geoip2.Open(s.asnPath)
		if err != nil {
			return fmt.Errorf("failed to open ASN database: %w", err)
		}
		s.asnDB = db
		if err := s.buildDatacenterSet(); err != nil {
			config.GetAppConfig().LogWarn("[MaxMind] Failed to build datacenter set: %v", err)
		}
	} else {
		config.GetAppConfig().LogWarn("[MaxMind] ASN database not found: %s", s.asnPath)
	}

	if s.countryDB == nil && s.asnDB == nil {
		return fmt.Errorf("no MaxMind databases found in %s", filepath.Dir(s.countryPath))
	}

	return nil
}

func (s *MaxMindService) buildDatacenterSet() error {
	if s.asnDB == nil {
		return fmt.Errorf("ASN database not loaded")
	}
	s.asnOrgMap = make(map[uint]string)
	s.datacenterASNs = make(map[uint]bool)

	// Open the raw MMDB to iterate all ASN networks and build ASN→Org map.
	db, err := maxminddb.Open(s.asnPath)
	if err != nil {
		return fmt.Errorf("failed to open ASN mmdb for iteration: %w", err)
	}
	defer db.Close()

	type asnRecord struct {
		ASN uint   `maxminddb:"autonomous_system_number"`
		Org string `maxminddb:"autonomous_system_organization"`
	}

	networks := db.Networks(maxminddb.SkipAliasedNetworks)
	for networks.Next() {
		var record asnRecord
		_, err := networks.Network(&record)
		if err != nil {
			continue
		}
		if record.ASN == 0 || record.Org == "" {
			continue
		}
		if _, exists := s.asnOrgMap[record.ASN]; !exists {
			s.asnOrgMap[record.ASN] = record.Org
			s.datacenterASNs[record.ASN] = isDatacenterOrg(record.Org)
		}
	}

	config.GetAppConfig().LogInfo("[MaxMind] Built ASN map: %d unique ASNs", len(s.asnOrgMap))
	return nil
}


func (s *MaxMindService) Lookup(ipStr string) (*GeoIPResult, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ipStr)
	}

	result := &GeoIPResult{}

	s.mu.Lock()
	defer s.mu.Unlock()


	if s.countryDB != nil {
		record, err := s.countryDB.Country(ip)
		if err == nil {
			result.Country = record.Country.Names["en"]
			result.CountryCode = record.Country.IsoCode
		}
	}


	if s.asnDB != nil {
		record, err := s.asnDB.ASN(ip)
		if err == nil {
			result.ASN = record.AutonomousSystemNumber
			result.ASNOrg = record.AutonomousSystemOrganization
			
			if s.asnOrgMap == nil {
				s.asnOrgMap = make(map[uint]string)
			}
			s.asnOrgMap[result.ASN] = result.ASNOrg
			
			if s.datacenterASNs == nil {
				s.datacenterASNs = make(map[uint]bool)
			}
			
			if _, exists := s.datacenterASNs[result.ASN]; !exists {
				isDatacenter := isDatacenterOrg(result.ASNOrg)
				s.datacenterASNs[result.ASN] = isDatacenter
				result.IsDatacenter = isDatacenter
				
				config.GetAppConfig().LogDebug("[MaxMind] ASN lookup: %d (%s) - IsDatacenter: %v", result.ASN, result.ASNOrg, isDatacenter)
				
				if isDatacenter {
					config.GetAppConfig().LogDebug("[MaxMind] Detected datacenter ASN: %d (%s)", result.ASN, result.ASNOrg)
				}
			} else {
				result.IsDatacenter = s.datacenterASNs[result.ASN]
				config.GetAppConfig().LogDebug("[MaxMind] Cached ASN lookup: %d - IsDatacenter: %v", result.ASN, result.IsDatacenter)
			}
		}
	}

	return result, nil
}


func (s *MaxMindService) IsDatacenterASN(asn uint) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.datacenterASNs == nil {
		return false
	}
	return s.datacenterASNs[asn]
}

func (s *MaxMindService) LookupASNOrg(asn uint) string {
	s.mu.RLock()
	if s.asnOrgMap != nil {
		if org, ok := s.asnOrgMap[asn]; ok {
			s.mu.RUnlock()
			return org
		}
	}
	s.mu.RUnlock()
	return ""
}

func isDatacenterOrg(orgName string) bool {
	if orgName == "" {
		return false
	}
	
	orgLower := strings.ToLower(orgName)
	
	datacenterKeywords := []string{
		// Major cloud providers
		"amazon", "aws", "ec2", "cloudfront",
		"google", "gcp", "google cloud",
		"microsoft", "azure", "windows azure",
		"alibaba", "aliyun",
		
		// Popular hosting/VPS providers
		"digitalocean", "linode", "vultr",
		"ovh", "hetzner", "hostpapa",
		"scaleway", "upcloud", "packet",
		
		// CDN providers
		"cloudflare", "fastly", "akamai", "keycdn",
		
		// Other datacenter indicators
		"datacenter", "colo", "hosting", "vps",
		"dedicated", "server", "cloud",
	}
	
	for _, keyword := range datacenterKeywords {
		if strings.Contains(orgLower, keyword) {
			return true
		}
	}
	
	return false
}


func (s *MaxMindService) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.countryDB != nil {
		if err := s.countryDB.Close(); err != nil {
			return err
		}
	}

	if s.asnDB != nil {
		if err := s.asnDB.Close(); err != nil {
			return err
		}
	}

	return nil
}
