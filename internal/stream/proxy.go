package stream

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/vibeswaf/waf/internal/config"
	"github.com/vibeswaf/waf/internal/domain/app"
	"github.com/vibeswaf/waf/internal/domain/ip_access"
)

type IPChecker interface {
	CheckIP(appID string, ip string) (*ip_access.IPAccessRule, error)
}

type Proxy struct {
	ipChecker  IPChecker
	appCfg     *config.AppConfig
	listeners  map[string]net.Listener
	udpConns   map[string]*net.UDPConn
	mu         sync.Mutex
	stopCh     chan struct{}
}

func NewProxy(ipChecker IPChecker) *Proxy {
	return &Proxy{
		ipChecker: ipChecker,
		appCfg:    config.GetAppConfig(),
		listeners: make(map[string]net.Listener),
		udpConns:  make(map[string]*net.UDPConn),
		stopCh:    make(chan struct{}),
	}
}

func (p *Proxy) StartForApp(a *app.App) error {
	if !a.IsStream() {
		return nil
	}

	scheme := a.StreamScheme()
	listenAddr := fmt.Sprintf(":%d", a.Config.ListenPort)

	switch scheme {
	case "tcp":
		return p.startTCP(a, listenAddr)
	case "udp":
		return p.startUDP(a, listenAddr)
	}
	return nil
}

func (p *Proxy) StopForApp(appID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if ln, ok := p.listeners[appID]; ok {
		ln.Close()
		delete(p.listeners, appID)
		p.appCfg.LogInfo("[STREAM] Stopped TCP listener for app=%s", appID)
	}

	if conn, ok := p.udpConns[appID]; ok {
		conn.Close()
		delete(p.udpConns, appID)
		p.appCfg.LogInfo("[STREAM] Stopped UDP listener for app=%s", appID)
	}
}

func (p *Proxy) Close() {
	close(p.stopCh)
	p.mu.Lock()
	defer p.mu.Unlock()

	for id, ln := range p.listeners {
		ln.Close()
		delete(p.listeners, id)
	}
	for id, conn := range p.udpConns {
		conn.Close()
		delete(p.udpConns, id)
	}
}

func (p *Proxy) startTCP(a *app.App, listenAddr string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen tcp %s: %w", listenAddr, err)
	}

	p.mu.Lock()
	p.listeners[a.ID] = ln
	p.mu.Unlock()

	p.appCfg.LogInfo("[STREAM] TCP listening on %s for app=%s", listenAddr, a.ID)

	go p.acceptTCP(a, ln)
	return nil
}

func (p *Proxy) acceptTCP(a *app.App, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
			}
			if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "use of closed network connection" {
				return
			}
			p.appCfg.LogError("[STREAM] TCP accept error app=%s: %v", a.ID, err)
			continue
		}

		go p.handleTCPConn(a, conn)
	}
}

func (p *Proxy) handleTCPConn(a *app.App, clientConn net.Conn) {
	defer clientConn.Close()

	clientIP := extractIP(clientConn.RemoteAddr().String())

	if !p.checkAccess(a, clientIP) {
		p.appCfg.LogInfo("[STREAM] TCP blocked ip=%s app=%s", clientIP, a.ID)
		return
	}

	upstream := a.PickUpstream(clientIP)
	if upstream == nil {
		p.appCfg.LogWarn("[STREAM] No upstream available app=%s", a.ID)
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)
	upstreamConn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		p.appCfg.LogError("[STREAM] TCP dial upstream failed app=%s target=%s: %v", a.ID, targetAddr, err)
		return
	}
	defer upstreamConn.Close()

	p.appCfg.LogDebug("[STREAM] TCP connected ip=%s -> %s app=%s", clientIP, targetAddr, a.ID)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(upstreamConn, clientConn)
		if tc, ok := upstreamConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(clientConn, upstreamConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()
}

func (p *Proxy) startUDP(a *app.App, listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve udp addr %s: %w", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen udp %s: %w", listenAddr, err)
	}

	p.mu.Lock()
	p.udpConns[a.ID] = conn
	p.mu.Unlock()

	p.appCfg.LogInfo("[STREAM] UDP listening on %s for app=%s", listenAddr, a.ID)

	go p.handleUDP(a, conn)
	return nil
}

func (p *Proxy) handleUDP(a *app.App, serverConn *net.UDPConn) {
	buf := make([]byte, 65535)
	sessions := &sync.Map{}

	for {
		n, clientAddr, err := serverConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
			}
			p.appCfg.LogError("[STREAM] UDP read error app=%s: %v", a.ID, err)
			continue
		}

		clientIP := clientAddr.IP.String()

		if !p.checkAccess(a, clientIP) {
			continue
		}

		upstream := a.PickUpstream(clientIP)
		if upstream == nil {
			continue
		}

		targetAddr := fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)
		sessionKey := clientAddr.String()

		val, loaded := sessions.LoadOrStore(sessionKey, nil)
		if !loaded {
			upstreamAddr, err := net.ResolveUDPAddr("udp", targetAddr)
			if err != nil {
				sessions.Delete(sessionKey)
				continue
			}
			upstreamConn, err := net.DialUDP("udp", nil, upstreamAddr)
			if err != nil {
				sessions.Delete(sessionKey)
				continue
			}
			sessions.Store(sessionKey, upstreamConn)

			go func(uc *net.UDPConn, ca *net.UDPAddr) {
				defer uc.Close()
				defer sessions.Delete(sessionKey)
				reply := make([]byte, 65535)
				uc.SetReadDeadline(time.Now().Add(30 * time.Second))
				for {
					rn, err := uc.Read(reply)
					if err != nil {
						return
					}
					serverConn.WriteToUDP(reply[:rn], ca)
					uc.SetReadDeadline(time.Now().Add(30 * time.Second))
				}
			}(upstreamConn, clientAddr)

			val = upstreamConn
		}

		if upstreamConn, ok := val.(*net.UDPConn); ok && upstreamConn != nil {
			upstreamConn.Write(buf[:n])
		}
	}
}

func (p *Proxy) checkAccess(a *app.App, clientIP string) bool {
	if a.UnderAttackMode {
		return false
	}

	if p.ipChecker != nil {
		rule, err := p.ipChecker.CheckIP(a.ID, clientIP)
		if err == nil && rule != nil && rule.Action == "block" {
			return false
		}
	}

	return true
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
