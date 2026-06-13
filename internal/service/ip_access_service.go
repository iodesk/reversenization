package service

import (
	"fmt"
	"net"

	"github.com/vibeswaf/waf/internal/domain/ip_access"
	"github.com/vibeswaf/waf/internal/repository"
)

type IPAccessService struct {
	repo repository.IPAccessRepository
}


func NewIPAccessService(repo repository.IPAccessRepository) *IPAccessService {
	return &IPAccessService{
		repo: repo,
	}
}


func (s *IPAccessService) List(appID string) ([]*ip_access.IPAccessRule, error) {
	return s.repo.ListByApp(appID)
}


func (s *IPAccessService) Create(req *ip_access.CreateRequest) (*ip_access.IPAccessRule, error) {
	if req.AppID == "" {
		return nil, fmt.Errorf("app_id is required")
	}

	if err := s.validateIPRange(req.IPRange); err != nil {
		return nil, err
	}

	if req.Action != "allow" && req.Action != "block" && req.Action != "challenge" {
		return nil, fmt.Errorf("invalid action: must be 'allow', 'block', or 'challenge'")
	}

	if err := s.checkOverlap(req.AppID, req.IPRange, 0); err != nil {
		return nil, err
	}

	return s.repo.Create(req)
}


func (s *IPAccessService) Update(appID string, id int, req *ip_access.UpdateRequest) (*ip_access.IPAccessRule, error) {
	existing, err := s.repo.GetByID(id)
	if err != nil {
		return nil, fmt.Errorf("ip access rule not found")
	}
	if existing.AppID != appID {
		return nil, fmt.Errorf("ip access rule not found")
	}

	if req.IPRange != "" {
		if err := s.validateIPRange(req.IPRange); err != nil {
			return nil, err
		}

		if err := s.checkOverlap(appID, req.IPRange, id); err != nil {
			return nil, err
		}
	}

	if req.Action != "" {
		if req.Action != "allow" && req.Action != "block" && req.Action != "challenge" {
			return nil, fmt.Errorf("invalid action: must be 'allow', 'block', or 'challenge'")
		}
	}

	return s.repo.Update(id, req)
}


func (s *IPAccessService) Delete(appID string, id int) error {
	existing, err := s.repo.GetByID(id)
	if err != nil {
		return fmt.Errorf("ip access rule not found")
	}
	if existing.AppID != appID {
		return fmt.Errorf("ip access rule not found")
	}

	return s.repo.Delete(id)
}


func (s *IPAccessService) CheckIP(appID string, ip string) (*ip_access.IPAccessRule, error) {
	return s.repo.CheckIP(appID, ip)
}


func (s *IPAccessService) validateIPRange(ipRange string) error {

	_, _, err := net.ParseCIDR(ipRange)
	if err == nil {
		return nil
	}


	ip := net.ParseIP(ipRange)
	if ip == nil {
		return fmt.Errorf("invalid IP address or CIDR notation: %s", ipRange)
	}





	return nil
}


func (s *IPAccessService) checkOverlap(appID string, ipRange string, excludeID int) error {

	rules, err := s.repo.ListByApp(appID)
	if err != nil {
		return fmt.Errorf("failed to check overlap: %w", err)
	}


	_, newNet, err := net.ParseCIDR(ipRange)
	if err != nil {

		ip := net.ParseIP(ipRange)
		if ip == nil {
			return fmt.Errorf("invalid IP range")
		}

		if ip.To4() != nil {
			ipRange = ipRange + "/32"
		} else {
			ipRange = ipRange + "/128"
		}
		_, newNet, _ = net.ParseCIDR(ipRange)
	}


	for _, rule := range rules {
		if rule.ID == excludeID {
			continue
		}

		_, existingNet, err := net.ParseCIDR(rule.IPRange)
		if err != nil {
			continue
		}


		if newNet.Contains(existingNet.IP) || existingNet.Contains(newNet.IP) {
			return fmt.Errorf("IP range overlaps with existing rule: %s (ID: %d)", rule.IPRange, rule.ID)
		}
	}

	return nil
}
