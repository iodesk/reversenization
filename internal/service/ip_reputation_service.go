package service

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/model"
	"github.com/vibeswaf/waf/internal/repository"
)

type IPReputationService struct {
	repo         *repository.IPReputationRepository
	settingsRepo *repository.SettingsRepository

	mu      sync.RWMutex
	ipMap   map[string]int
	asnMap  map[uint]int
	cidrMap []cidrEntry

	// cfg is the cached IP reputation config, read via atomic load on the hot
	// path to avoid a DB query during MaxMind auto-detect scoring.
	cfg unsafe.Pointer // *model.IPReputationConfig
}

type cidrEntry struct {
	network *net.IPNet
	score   int
}

func NewIPReputationService(repo *repository.IPReputationRepository, settingsRepo *repository.SettingsRepository) *IPReputationService {
	s := &IPReputationService{
		repo:         repo,
		settingsRepo: settingsRepo,
		ipMap:        make(map[string]int),
		asnMap:       make(map[uint]int),
	}
	s.Reload()
	return s
}

func (s *IPReputationService) Reload() {
	if cfg, err := s.settingsRepo.GetIPReputationConfig(); err == nil {
		atomic.StorePointer(&s.cfg, unsafe.Pointer(&cfg))
	} else if atomic.LoadPointer(&s.cfg) == nil {
		def := model.DefaultIPReputationConfig()
		atomic.StorePointer(&s.cfg, unsafe.Pointer(&def))
	}

	entries, err := s.repo.ListEnabled()
	if err != nil {
		config.GetAppConfig().LogError("[IP_REPUTATION] Failed to load entries: %v", err)
		return
	}

	ipMap := make(map[string]int)
	asnMap := make(map[uint]int)
	var cidrList []cidrEntry

	for _, e := range entries {
		switch e.EntryType {
		case "ip":
			_, ipNet, err := net.ParseCIDR(e.Value)
			if err == nil {
				cidrList = append(cidrList, cidrEntry{network: ipNet, score: e.Score})
			} else {
				ip := net.ParseIP(e.Value)
				if ip != nil {
					ipMap[ip.String()] = e.Score
				}
			}
		case "asn":
			asn, err := strconv.ParseUint(e.Value, 10, 32)
			if err == nil {
				asnMap[uint(asn)] = e.Score
			}
		}
	}

	s.mu.Lock()
	s.ipMap = ipMap
	s.asnMap = asnMap
	s.cidrMap = cidrList
	s.mu.Unlock()

	config.GetAppConfig().LogDebug("[IP_REPUTATION] Loaded %d IP entries, %d CIDR entries, %d ASN entries",
		len(ipMap), len(cidrList), len(asnMap))
}

func (s *IPReputationService) LookupIP(ipStr string) (int, bool) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if score, ok := s.ipMap[ip.String()]; ok {
		return score, true
	}

	for _, entry := range s.cidrMap {
		if entry.network.Contains(ip) {
			return entry.score, true
		}
	}

	return 0, false
}

func (s *IPReputationService) LookupASN(asn uint) (int, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if score, ok := s.asnMap[asn]; ok {
		return score, true
	}
	return 0, false
}

func (s *IPReputationService) GetConfig() (model.IPReputationConfig, error) {
	if p := (*model.IPReputationConfig)(atomic.LoadPointer(&s.cfg)); p != nil {
		return *p, nil
	}
	return s.settingsRepo.GetIPReputationConfig()
}

func (s *IPReputationService) UpdateConfig(cfg model.IPReputationConfig) error {
	if err := s.settingsRepo.UpdateIPReputationConfig(cfg); err != nil {
		return err
	}
	atomic.StorePointer(&s.cfg, unsafe.Pointer(&cfg))
	return nil
}

func (s *IPReputationService) List() ([]*model.IPReputationEntry, error) {
	return s.repo.List()
}

func (s *IPReputationService) Create(e *model.IPReputationEntry) error {
	if e.EntryType != "ip" && e.EntryType != "asn" {
		return fmt.Errorf("invalid entry_type: must be 'ip' or 'asn'")
	}

	if e.Value == "" {
		return fmt.Errorf("value is required")
	}

	if e.Score < 1 || e.Score > 100 {
		return fmt.Errorf("score must be between 1 and 100")
	}

	if e.EntryType == "ip" {
		if err := validateIPOrCIDR(e.Value); err != nil {
			return err
		}
	}

	if e.EntryType == "asn" {
		if _, err := strconv.ParseUint(e.Value, 10, 32); err != nil {
			return fmt.Errorf("invalid ASN number: %s", e.Value)
		}
	}

	if err := s.repo.Create(e); err != nil {
		return err
	}

	s.Reload()
	return nil
}

func (s *IPReputationService) BulkCreate(entries []*model.IPReputationEntry) (created []*model.IPReputationEntry, errors []string) {
	for _, e := range entries {
		if e.EntryType != "ip" && e.EntryType != "asn" {
			errors = append(errors, e.Value+": invalid entry_type")
			continue
		}
		if e.Value == "" {
			errors = append(errors, "empty value")
			continue
		}
		if e.Score < 1 || e.Score > 100 {
			errors = append(errors, e.Value+": score must be between 1 and 100")
			continue
		}
		if e.EntryType == "ip" {
			if err := validateIPOrCIDR(e.Value); err != nil {
				errors = append(errors, e.Value+": "+err.Error())
				continue
			}
		}
		if e.EntryType == "asn" {
			if _, err := strconv.ParseUint(e.Value, 10, 32); err != nil {
				errors = append(errors, e.Value+": invalid ASN number")
				continue
			}
		}
		inserted, err := s.repo.Upsert(e)
		if err != nil {
			errors = append(errors, e.Value+": "+err.Error())
			continue
		}
		if inserted {
			created = append(created, e)
		}
	}

	if len(created) > 0 {
		s.Reload()
	}
	return
}

func (s *IPReputationService) Update(e *model.IPReputationEntry) error {
	if e.EntryType != "ip" && e.EntryType != "asn" {
		return fmt.Errorf("invalid entry_type: must be 'ip' or 'asn'")
	}

	if e.Value == "" {
		return fmt.Errorf("value is required")
	}

	if e.Score < 1 || e.Score > 100 {
		return fmt.Errorf("score must be between 1 and 100")
	}

	if e.EntryType == "ip" {
		if err := validateIPOrCIDR(e.Value); err != nil {
			return err
		}
	}

	if e.EntryType == "asn" {
		if _, err := strconv.ParseUint(e.Value, 10, 32); err != nil {
			return fmt.Errorf("invalid ASN number: %s", e.Value)
		}
	}

	if err := s.repo.Update(e); err != nil {
		return err
	}

	s.Reload()
	return nil
}

func (s *IPReputationService) Delete(id int) error {
	if err := s.repo.Delete(id); err != nil {
		return err
	}

	s.Reload()
	return nil
}

func (s *IPReputationService) BulkDelete(ids []int) (int64, error) {
	n, err := s.repo.BulkDelete(ids)
	if err != nil {
		return 0, err
	}
	s.Reload()
	return n, nil
}

func (s *IPReputationService) BulkUpdateScore(ids []int, score int) (int64, error) {
	n, err := s.repo.BulkUpdateScore(ids, score)
	if err != nil {
		return 0, err
	}
	s.Reload()
	return n, nil
}

func validateIPOrCIDR(value string) error {
	_, _, err := net.ParseCIDR(value)
	if err == nil {
		return nil
	}

	ip := net.ParseIP(value)
	if ip == nil {
		return fmt.Errorf("invalid IP address or CIDR: %s", value)
	}
	return nil
}

func (s *IPReputationService) SyncSpamhaus() (int, int, []string, error) {
	cfg, _ := s.GetConfig()
	ipScore := cfg.SpamhausIPScore
	if ipScore == 0 {
		ipScore = 50
	}
	asnScore := cfg.SpamhausASNScore
	if asnScore == 0 {
		asnScore = 50
	}

	var totalIPs, totalASNs int
	var fetchErrors []string

	// Fetch DROP v4
	v4CIDRs, err := fetchSpamhausDROPv4()
	if err != nil {
		config.GetAppConfig().LogError("[SPAMHAUS] Failed to fetch DROPv4: %v", err)
		fetchErrors = append(fetchErrors, "DROPv4: "+err.Error())
	} else {
		for _, cidr := range v4CIDRs {
			entry := &model.IPReputationEntry{
				EntryType:   "ip",
				Value:       cidr,
				Score:       ipScore,
				Description: "Spamhaus DROP",
				Enabled:     true,
			}
			if inserted, _ := s.repo.Upsert(entry); inserted {
				totalIPs++
			}
		}
	}

	// Fetch DROP v6
	v6CIDRs, err := fetchSpamhausDROPv6()
	if err != nil {
		config.GetAppConfig().LogError("[SPAMHAUS] Failed to fetch DROPv6: %v", err)
		fetchErrors = append(fetchErrors, "DROPv6: "+err.Error())
	} else {
		for _, cidr := range v6CIDRs {
			entry := &model.IPReputationEntry{
				EntryType:   "ip",
				Value:       cidr,
				Score:       ipScore,
				Description: "Spamhaus DROPv6",
				Enabled:     true,
			}
			if inserted, _ := s.repo.Upsert(entry); inserted {
				totalIPs++
			}
		}
	}

	// Fetch ASN-DROP
	asns, err := fetchSpamhausASNDROP()
	if err != nil {
		config.GetAppConfig().LogError("[SPAMHAUS] Failed to fetch ASN-DROP: %v", err)
		fetchErrors = append(fetchErrors, "ASN-DROP: "+err.Error())
	} else {
		for _, asn := range asns {
			entry := &model.IPReputationEntry{
				EntryType:   "asn",
				Value:       strconv.FormatUint(uint64(asn), 10),
				Score:       asnScore,
				Description: "Spamhaus ASN-DROP",
				Enabled:     true,
			}
			if inserted, _ := s.repo.Upsert(entry); inserted {
				totalASNs++
			}
		}
	}

	s.Reload()
	config.GetAppConfig().LogInfo("[SPAMHAUS] Synced %d IPs, %d ASNs, errors: %d", totalIPs, totalASNs, len(fetchErrors))
	return totalIPs, totalASNs, fetchErrors, nil
}
