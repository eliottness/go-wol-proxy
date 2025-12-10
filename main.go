package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"golang.org/x/crypto/ssh"
)

// Interfaces for dependency injection
type HealthChecker interface {
	Check(ctx context.Context, endpoint string) bool
	StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration)
	WaitForInitialChecks(ctx context.Context) error
}

type WOLSender interface {
	SendWOL(macAddr, broadcastIP string, port int) error
}

type SSHExecutor interface {
	ExecuteCommand(host, user, keyPath, command string) error
}

type Logger interface {
	Info(msg string, args ...interface{})
	Error(msg string, args ...interface{})
}

// Config structs
type Config struct {
	Timeout             string   `toml:"timeout"`
	PollInterval        string   `toml:"poll_interval"`
	HealthCheckInterval string   `toml:"health_check_interval"`
	HealthCacheDuration string   `toml:"health_cache_duration"`
	Targets             []Target `toml:"targets"`
}

type Target struct {
	Name                 string `toml:"name"`
	ListenPort           int    `toml:"listen_port"`           // Port to listen on for this target
	DestinationHost      string `toml:"destination_host"`      // Target host (IP or hostname)
	DestinationPort      int    `toml:"destination_port"`      // Target port
	Protocol             string `toml:"protocol"`              // "tcp" or "udp"
	HealthCheckHost      string `toml:"health_check_host"`     // Health check host
	HealthCheckPort      int    `toml:"health_check_port"`     // Health check port
	MacAddress           string `toml:"mac_address"`
	BroadcastIP          string `toml:"broadcast_ip"`
	WolPort              int    `toml:"wol_port"`
	SSHHost              string `toml:"ssh_host"`
	SSHUser              string `toml:"ssh_user"`
	SSHKeyPath           string `toml:"ssh_key_path"`
	ShutdownCommand      string `toml:"shutdown_command"`
	ShutdownHTTPUrl      string `toml:"shutdown_http_url"`
	ShutdownHTTPMethod   string `toml:"shutdown_http_method"`
	ShutdownHTTPOKStatus int    `toml:"shutdown_http_ok_status"`
	InactivityThreshold  string `toml:"inactivity_threshold"`
}

type ProxyConfig struct {
	Timeout              time.Duration
	PollInterval         time.Duration
	HealthCheckInterval  time.Duration
	HealthCacheDuration  time.Duration
	Targets              map[string]*TargetState
	InactivityThresholds map[string]time.Duration // target name -> inactivity threshold
}

type TargetState struct {
	Target       *Target
	IsHealthy    bool
	LastCheck    time.Time
	IsWaking     bool
	LastActivity time.Time
	mu           sync.RWMutex
}

// TCP Health Checker implementation
type TCPHealthChecker struct {
	logger           Logger
	initialCheckDone map[string]bool
	initialCheckMu   sync.RWMutex
	initialWaitGroup sync.WaitGroup
}

func NewTCPHealthChecker(logger Logger) *TCPHealthChecker {
	return &TCPHealthChecker{
		logger:           logger,
		initialCheckDone: make(map[string]bool),
	}
}

func (h *TCPHealthChecker) Check(ctx context.Context, endpoint string) bool {
	// endpoint format: "host:port"
	dialer := net.Dialer{
		Timeout: 5 * time.Second,
	}
	
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return false
	}
	defer conn.Close()
	
	return true
}

func (h *TCPHealthChecker) StartBackgroundChecks(ctx context.Context, targets map[string]*TargetState, interval time.Duration) {
	for name, target := range targets {
		h.initialWaitGroup.Add(1)
		go h.backgroundCheck(ctx, name, target, interval)
	}
}

func (h *TCPHealthChecker) WaitForInitialChecks(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		h.initialWaitGroup.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (h *TCPHealthChecker) backgroundCheck(ctx context.Context, name string, target *TargetState, interval time.Duration) {
	// Perform initial check
	h.performCheck(name, target)
	h.markInitialCheckDone(name)
	h.initialWaitGroup.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			h.performCheck(name, target)
		}
	}
}

func (h *TCPHealthChecker) performCheck(name string, target *TargetState) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	endpoint := net.JoinHostPort(target.Target.HealthCheckHost, strconv.Itoa(target.Target.HealthCheckPort))
	healthy := h.Check(ctx, endpoint)

	target.mu.Lock()
	previousHealth := target.IsHealthy
	target.IsHealthy = healthy
	target.LastCheck = time.Now()
	target.mu.Unlock()

	if healthy != previousHealth {
		status := "DOWN"
		if healthy {
			status = "UP"
		}
		h.logger.Info("Health check for %s (%s:%d): %s", name, target.Target.HealthCheckHost, target.Target.HealthCheckPort, status)
	}
}

func (h *TCPHealthChecker) markInitialCheckDone(name string) {
	h.initialCheckMu.Lock()
	defer h.initialCheckMu.Unlock()
	h.initialCheckDone[name] = true
}

// Wake-on-LAN sender implementation
type UDPWOLSender struct {
	logger Logger
}

func NewUDPWOLSender(logger Logger) *UDPWOLSender {
	return &UDPWOLSender{logger: logger}
}

// SSH command executor implementation
type DefaultSSHExecutor struct {
	logger Logger
}

func NewDefaultSSHExecutor(logger Logger) *DefaultSSHExecutor {
	return &DefaultSSHExecutor{logger: logger}
}

func (s *DefaultSSHExecutor) ExecuteCommand(host, user, keyPath, command string) error {
	// Read private key
	key, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("unable to read private key: %w", err)
	}

	// Create signer
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("unable to parse private key: %w", err)
	}

	// Configure SSH client
	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	// Connect to SSH server
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return fmt.Errorf("unable to connect to SSH server: %w", err)
	}
	defer client.Close()

	// Create session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("unable to create SSH session: %w", err)
	}
	defer session.Close()

	// Execute command
	s.logger.Info("Executing SSH command on %s@%s: %s", user, host, command)
	output, err := session.CombinedOutput(command)
	if err != nil {
		return fmt.Errorf("command execution failed: %w, output: %s", err, string(output))
	}

	s.logger.Info("SSH command executed successfully on %s@%s, output: %s", user, host, string(output))
	return nil
}

func (w *UDPWOLSender) SendWOL(macAddr, broadcastIP string, port int) error {
	// Parse MAC address
	mac, err := net.ParseMAC(macAddr)
	if err != nil {
		return fmt.Errorf("invalid MAC address: %w", err)
	}

	// Create magic packet
	packet := w.createMagicPacket(mac)

	// Send UDP packet
	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", broadcastIP, port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	_, err = conn.Write(packet)
	if err != nil {
		return fmt.Errorf("failed to send WOL packet: %w", err)
	}

	w.logger.Info("WOL packet sent to %s via %s:%d", macAddr, broadcastIP, port)
	return nil
}

func (w *UDPWOLSender) createMagicPacket(mac net.HardwareAddr) []byte {
	var packet bytes.Buffer

	// 6 bytes of 0xFF
	for i := 0; i < 6; i++ {
		packet.WriteByte(0xFF)
	}

	// 16 repetitions of the MAC address
	for i := 0; i < 16; i++ {
		packet.Write(mac)
	}

	return packet.Bytes()
}

// Main proxy service
type ProxyService struct {
	config        *ProxyConfig
	healthChecker HealthChecker
	wolSender     WOLSender
	sshExecutor   SSHExecutor
	logger        Logger
}

func NewProxyService(
	config *ProxyConfig,
	healthChecker HealthChecker,
	wolSender WOLSender,
	sshExecutor SSHExecutor,
	logger Logger,
) *ProxyService {
	return &ProxyService{
		config:        config,
		healthChecker: healthChecker,
		wolSender:     wolSender,
		sshExecutor:   sshExecutor,
		logger:        logger,
	}
}

func (p *ProxyService) shutdownTarget(targetName string) error {
	targetState, exists := p.config.Targets[targetName]
	if !exists {
		return fmt.Errorf("unknown target: %s", targetName)
	}

	target := targetState.Target
    if (target.SSHHost == "" || target.SSHUser == "" || target.SSHKeyPath == "" || target.ShutdownCommand == "") && target.ShutdownHTTPUrl == "" {
        return fmt.Errorf("target %s is missing SSH configuration or shutdown command or shutdown HTTP URL", targetName)
    }

	p.logger.Info("Shutting down target %s (%s:%d) due to inactivity", targetName, target.DestinationHost, target.DestinationPort)
	if target.ShutdownHTTPUrl != "" {
		// Attempt to shut down via HTTP request
		method := target.ShutdownHTTPMethod
		if method == "" {
			method = "POST" // Default to POST if not specified
		}

        req, err := http.NewRequest(method, target.ShutdownHTTPUrl, nil)
        if err != nil {
            return fmt.Errorf("failed to create shutdown request: %w", err)
        }

		// Send the request
		client := &http.Client{
			Timeout: 10 * time.Second,
		}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("failed to send shutdown request: %w", err)
		}
		defer resp.Body.Close()

        // Accept any 2xx status by default; allow explicit status override
        if target.ShutdownHTTPOKStatus != 0 {
            if resp.StatusCode != target.ShutdownHTTPOKStatus {
                return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
            }
        } else if resp.StatusCode < 200 || resp.StatusCode >= 300 {
            return fmt.Errorf("shutdown request failed with status: %s", resp.Status)
        }

	} else {
		err := p.sshExecutor.ExecuteCommand(target.SSHHost, target.SSHUser, target.SSHKeyPath, target.ShutdownCommand)
		if err != nil {
			p.logger.Error("Failed to shut down target %s: %v", targetName, err)
			return err
		}
	}

	// Mark the target as unhealthy after shutdown
	targetState.mu.Lock()
	targetState.IsHealthy = false
	targetState.mu.Unlock()

	p.logger.Info("Target %s (%s:%d) has been shut down", targetName, target.DestinationHost, target.DestinationPort)
	return nil
}

func (p *ProxyService) startInactivityMonitor(ctx context.Context) {
	// Check every 10 seconds for inactive targets
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.checkInactiveTargets()
		}
	}
}

func (p *ProxyService) checkInactiveTargets() {
	now := time.Now()

	for name, targetState := range p.config.Targets {
		// Skip targets without inactivity threshold
		threshold, exists := p.config.InactivityThresholds[name]
		if !exists {
			continue
		}

		// Skip targets that are not healthy (already down)
		targetState.mu.RLock()
		isHealthy := targetState.IsHealthy
		lastActivity := targetState.LastActivity
		targetState.mu.RUnlock()

		if !isHealthy {
			continue
		}

		// Check if the target has been inactive for too long
		inactiveDuration := now.Sub(lastActivity)
		if inactiveDuration > threshold {
			p.logger.Info("Target %s has been inactive for %v (threshold: %v), shutting down",
				name, inactiveDuration.Round(time.Second), threshold)

			if err := p.shutdownTarget(name); err != nil {
				p.logger.Error("Failed to shut down inactive target %s: %v", name, err)
			}
		}
	}
}

func (p *ProxyService) Start(ctx context.Context) error {
	// Start background health checks
	p.healthChecker.StartBackgroundChecks(
		ctx,
		p.config.Targets,
		p.config.HealthCheckInterval,
	)

	// Wait for initial health checks to complete
	p.logger.Info("Waiting for initial health checks to complete...")
	if err := p.healthChecker.WaitForInitialChecks(ctx); err != nil {
		return fmt.Errorf("initial health checks failed: %w", err)
	}

	// Start background inactivity monitor
	go p.startInactivityMonitor(ctx)

	p.logger.Info("Initial health checks completed, starting TCP/UDP listeners")

	// Log configured targets and start listeners for each
	var wg sync.WaitGroup
	for name, targetState := range p.config.Targets {
		target := targetState.Target
		p.logger.Info("Configured target: %s -> %s:%d (listen on :%d, protocol: %s)",
			name, target.DestinationHost, target.DestinationPort, target.ListenPort, target.Protocol)
		
		wg.Add(1)
		go func(name string, target *Target) {
			defer wg.Done()
			if err := p.startListener(ctx, name, target); err != nil {
				p.logger.Error("Failed to start listener for %s: %v", name, err)
			}
		}(name, target)
	}

	// Wait for all listeners to complete (which should be never in normal operation)
	wg.Wait()
	return nil
}

func (p *ProxyService) startListener(ctx context.Context, targetName string, target *Target) error {
	protocol := target.Protocol
	if protocol == "" {
		protocol = "tcp" // default to TCP
	}
	
	// Validate protocol
	if protocol != "tcp" && protocol != "udp" {
		return fmt.Errorf("unsupported protocol: %s (must be 'tcp' or 'udp')", protocol)
	}

	listenAddr := fmt.Sprintf(":%d", target.ListenPort)
	
	if protocol == "tcp" {
		return p.startTCPListener(ctx, targetName, target, listenAddr)
	} else if protocol == "udp" {
		return p.startUDPListener(ctx, targetName, target, listenAddr)
	}
	
	return fmt.Errorf("unsupported protocol: %s", protocol)
}

func (p *ProxyService) startTCPListener(ctx context.Context, targetName string, target *Target, listenAddr string) error {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}
	defer listener.Close()

	p.logger.Info("TCP listener started for %s on %s", targetName, listenAddr)

	// Accept connections in a loop
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			conn, err := listener.Accept()
			if err != nil {
				p.logger.Error("Failed to accept connection for %s: %v", targetName, err)
				continue
			}

			// Handle connection in a goroutine
			go p.handleTCPConnection(ctx, targetName, target, conn)
		}
	}
}

func (p *ProxyService) startUDPListener(ctx context.Context, targetName string, target *Target, listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address %s: %w", listenAddr, err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP %s: %w", listenAddr, err)
	}
	defer conn.Close()

	p.logger.Info("UDP listener started for %s on %s", targetName, listenAddr)

	// Read and forward UDP packets
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			buffer := make([]byte, 65535) // Max UDP packet size
			n, clientAddr, err := conn.ReadFromUDP(buffer)
			if err != nil {
				p.logger.Error("Failed to read UDP packet for %s: %v", targetName, err)
				continue
			}

			// Copy the data to avoid race condition since we're passing to goroutine
			packetData := make([]byte, n)
			copy(packetData, buffer[:n])

			// Handle packet in a goroutine
			go p.handleUDPPacket(ctx, targetName, target, packetData, clientAddr, conn)
		}
	}
}

func (p *ProxyService) handleTCPConnection(ctx context.Context, targetName string, target *Target, clientConn net.Conn) {
	defer clientConn.Close()

	p.logger.Info("Incoming TCP connection for %s from %s", targetName, clientConn.RemoteAddr())

	targetState, exists := p.config.Targets[targetName]
	if !exists {
		p.logger.Error("Unknown target: %s", targetName)
		return
	}

	// Check if we have fresh health data
	if !p.isHealthyCached(targetState) {
		// Need to wake up the server
		p.logger.Info("Target %s appears down, attempting to wake", targetName)
		if err := p.wakeAndWait(ctx, targetState); err != nil {
			p.logger.Error("Failed to wake target %s: %v", targetName, err)
			return
		}
		p.logger.Info("Target %s is now healthy", targetName)
	}

	// Update last activity
	targetState.mu.Lock()
	targetState.LastActivity = time.Now()
	targetState.mu.Unlock()

	// Connect to target
	targetAddr := net.JoinHostPort(target.DestinationHost, strconv.Itoa(target.DestinationPort))
	targetConn, err := net.DialTimeout("tcp", targetAddr, 30*time.Second)
	if err != nil {
		p.logger.Error("Failed to connect to target %s at %s: %v", targetName, targetAddr, err)
		return
	}
	defer targetConn.Close()

	p.logger.Info("Connected to target %s at %s, forwarding data", targetName, targetAddr)

	// Forward data bidirectionally using sendfile when possible
	p.forwardTCP(clientConn, targetConn, targetName)
}

func (p *ProxyService) handleUDPPacket(ctx context.Context, targetName string, target *Target, data []byte, clientAddr *net.UDPAddr, serverConn *net.UDPConn) {
	p.logger.Info("Incoming UDP packet for %s from %s (%d bytes)", targetName, clientAddr, len(data))

	targetState, exists := p.config.Targets[targetName]
	if !exists {
		p.logger.Error("Unknown target: %s", targetName)
		return
	}

	// Check if we have fresh health data
	if !p.isHealthyCached(targetState) {
		// Need to wake up the server
		p.logger.Info("Target %s appears down, attempting to wake", targetName)
		if err := p.wakeAndWait(ctx, targetState); err != nil {
			p.logger.Error("Failed to wake target %s: %v", targetName, err)
			return
		}
		p.logger.Info("Target %s is now healthy", targetName)
	}

	// Update last activity
	targetState.mu.Lock()
	targetState.LastActivity = time.Now()
	targetState.mu.Unlock()

	// Forward to target
	targetAddr := net.JoinHostPort(target.DestinationHost, strconv.Itoa(target.DestinationPort))
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		p.logger.Error("Failed to resolve target address %s: %v", targetAddr, err)
		return
	}

	targetConn, err := net.DialUDP("udp", nil, targetUDPAddr)
	if err != nil {
		p.logger.Error("Failed to dial target %s: %v", targetAddr, err)
		return
	}
	defer targetConn.Close()

	// Send packet to target
	_, err = targetConn.Write(data)
	if err != nil {
		p.logger.Error("Failed to forward UDP packet to target %s: %v", targetName, err)
		return
	}

	// Read response from target and send back to client
	targetConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 65535) // Max UDP packet size
	n, err := targetConn.Read(response)
	if err != nil {
		// UDP is connectionless, no response is expected in many cases
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			p.logger.Info("No response from target %s (timeout)", targetName)
			return
		}
		p.logger.Error("Failed to read response from target %s: %v", targetName, err)
		return
	}

	// Send response back to client
	_, err = serverConn.WriteToUDP(response[:n], clientAddr)
	if err != nil {
		p.logger.Error("Failed to send response to client: %v", err)
		return
	}

	p.logger.Info("Forwarded UDP response to client (%d bytes)", n)
}

// forwardTCP copies data bidirectionally between client and target connections
// Uses sendfile(2) when possible for zero-copy transfer
func (p *ProxyService) forwardTCP(client, target net.Conn, targetName string) {
	var wg sync.WaitGroup
	wg.Add(2)

	// Client -> Target
	go func() {
		defer wg.Done()
		if err := p.copyData(client, target, "client->target"); err != nil && err != io.EOF {
			p.logger.Error("Error forwarding client->target for %s: %v", targetName, err)
		}
		// Close target write side to signal EOF
		if tc, ok := target.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// Target -> Client
	go func() {
		defer wg.Done()
		if err := p.copyData(target, client, "target->client"); err != nil && err != io.EOF {
			p.logger.Error("Error forwarding target->client for %s: %v", targetName, err)
		}
		// Close client write side to signal EOF
		if cc, ok := client.(*net.TCPConn); ok {
			cc.CloseWrite()
		}
	}()

	wg.Wait()
	p.logger.Info("Connection closed for %s", targetName)
}

// copyData attempts to use sendfile(2) for zero-copy transfer when possible,
// falls back to io.Copy if sendfile is not available
func (p *ProxyService) copyData(dst, src net.Conn, direction string) error {
	// Try to get file descriptors for sendfile on Linux
	srcFile, srcOK := getSysConn(src)
	dstFile, dstOK := getSysConn(dst)

	if srcOK && dstOK {
		// Both are file descriptors, try sendfile
		srcFd := int(srcFile.Fd())
		dstFd := int(dstFile.Fd())
		
		// Note: Do NOT close srcFile/dstFile here as they are references to the underlying
		// connection file descriptors. Closing them would terminate the connection.
		
		// Use splice/sendfile on Linux for zero-copy
		err := p.sendfileLoop(dstFd, srcFd, direction)
		if err != nil {
			// If splice fails (e.g., on non-Linux systems), fallback to io.Copy
			_, copyErr := io.Copy(dst, src)
			return copyErr
		}
		return nil
	}

	// Fallback to regular io.Copy
	_, err := io.Copy(dst, src)
	return err
}

// getSysConn extracts the underlying file from a net.Conn
func getSysConn(conn net.Conn) (*os.File, bool) {
	if tc, ok := conn.(*net.TCPConn); ok {
		if f, err := tc.File(); err == nil {
			return f, true
		}
	}
	return nil, false
}

// sendfileLoop uses sendfile(2) syscall for zero-copy data transfer on Linux
// Returns an error if splice is not available or fails
func (p *ProxyService) sendfileLoop(dst, src int, direction string) error {
	// Create a pipe for splice operations
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		// Pipe creation failed, caller will fallback to io.Copy
		return err
	}
	defer pipeR.Close()
	defer pipeW.Close()

	pipeRFd := int(pipeR.Fd())
	pipeWFd := int(pipeW.Fd())

	// Use splice to move data: src -> pipe -> dst
	// This is zero-copy on Linux
	for {
		// Splice from source to pipe
		n, err := syscall.Splice(src, nil, pipeWFd, nil, 65536, 0)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EINTR {
				continue
			}
			// Any other error (including ENOSYS on non-Linux) should trigger fallback
			return err
		}
		if n == 0 {
			return nil
		}

		// Splice from pipe to destination
		written := int64(0)
		for written < n {
			w, err := syscall.Splice(pipeRFd, nil, dst, nil, int(n-written), 0)
			if err != nil {
				if err == syscall.EAGAIN || err == syscall.EINTR {
					continue
				}
				return err
			}
			if w == 0 {
				return nil
			}
			written += w
		}
	}
}

func (p *ProxyService) isHealthyCached(target *TargetState) bool {
	target.mu.RLock()
	defer target.mu.RUnlock()

	if !target.IsHealthy {
		return false
	}

	return time.Since(target.LastCheck) <= p.config.HealthCacheDuration
}

func (p *ProxyService) wakeAndWait(ctx context.Context, target *TargetState) error {
	target.mu.Lock()
	if target.IsWaking {
		target.mu.Unlock()
		return p.waitForWake(ctx, target)
	}

	target.IsWaking = true
	target.mu.Unlock()

	err := p.wolSender.SendWOL(
		target.Target.MacAddress,
		target.Target.BroadcastIP,
		target.Target.WolPort,
	)

	target.mu.Lock()
	target.LastActivity = time.Now()
	target.IsWaking = false
	target.mu.Unlock()

	if err != nil {
		return fmt.Errorf("failed to send WOL: %w", err)
	}

	p.logger.Info("WOL packet sent to %s (%s:%d), waiting for server to wake",
		target.Target.Name, target.Target.DestinationHost, target.Target.DestinationPort)

	return p.waitForWake(ctx, target)
}

func (p *ProxyService) waitForWake(ctx context.Context, target *TargetState) error {
	timeout := time.After(p.config.Timeout)
	healthCheckTicker := time.NewTicker(p.config.PollInterval)
	defer healthCheckTicker.Stop()

	// Create a separate ticker for sending WOL packets
	// Send a packet once per second
	wolTicker := time.NewTicker(500 * time.Millisecond)
	defer wolTicker.Stop()

	wakeStartTime := time.Now()
	healthEndpoint := net.JoinHostPort(target.Target.HealthCheckHost, strconv.Itoa(target.Target.HealthCheckPort))

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			target.mu.Lock()
			target.IsWaking = false
			target.mu.Unlock()
			return fmt.Errorf("timeout waiting for %s to wake up after %v",
				target.Target.Name, p.config.Timeout)
		case <-wolTicker.C:
			// Send additional WOL packets while waiting
			err := p.wolSender.SendWOL(
				target.Target.MacAddress,
				target.Target.BroadcastIP,
				target.Target.WolPort,
			)
			if err != nil {
				p.logger.Error("Failed to send additional WOL packet: %v", err)
				// Continue waiting even if a packet fails to send
			} else {
				p.logger.Info("Sent additional WOL packet to %s (%s:%d)",
					target.Target.Name, target.Target.DestinationHost, target.Target.DestinationPort)
			}
		case <-healthCheckTicker.C:
			if p.healthChecker.Check(ctx, healthEndpoint) {
				target.mu.Lock()
				target.IsHealthy = true
				target.LastCheck = time.Now()
				target.IsWaking = false
				target.mu.Unlock()

				wakeDuration := time.Since(wakeStartTime)
				p.logger.Info("Target %s (%s:%d) woke up after %v",
					target.Target.Name, target.Target.DestinationHost, target.Target.DestinationPort, wakeDuration)
				return nil
			}
		}

		target.mu.Lock()
		target.IsWaking = false
		target.mu.Unlock()
	}
}

// Config loader
func LoadConfig(filename string) (*ProxyConfig, error) {
	var config Config
	_, err := toml.DecodeFile(filename, &config)
	if err != nil {
		return nil, err
	}

	// Set defaults
	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	pollInterval, err := time.ParseDuration(config.PollInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid poll_interval: %w", err)
	}

	healthCheckInterval, err := time.ParseDuration(config.HealthCheckInterval)
	if err != nil {
		return nil, fmt.Errorf("invalid health_check_interval: %w", err)
	}

	healthCacheDuration, err := time.ParseDuration(config.HealthCacheDuration)
	if err != nil {
		return nil, fmt.Errorf("invalid health_cache_duration: %w", err)
	}

	targets := make(map[string]*TargetState)
	inactivityThresholds := make(map[string]time.Duration)
	listenPorts := make(map[int]string) // port -> target name for duplicate check

    for _, target := range config.Targets {
        // Validate required fields
        if target.ListenPort <= 0 || target.ListenPort > 65535 {
            return nil, fmt.Errorf("target %s has invalid listen_port %d (must be 1-65535)", target.Name, target.ListenPort)
        }
        
        // Check for duplicate listen ports
        if existingTarget, exists := listenPorts[target.ListenPort]; exists {
            return nil, fmt.Errorf("duplicate listen_port %d for targets %s and %s", target.ListenPort, existingTarget, target.Name)
        }
        listenPorts[target.ListenPort] = target.Name
        
        if target.DestinationHost == "" {
            return nil, fmt.Errorf("target %s is missing destination_host", target.Name)
        }
        if target.DestinationPort <= 0 || target.DestinationPort > 65535 {
            return nil, fmt.Errorf("target %s has invalid destination_port %d (must be 1-65535)", target.Name, target.DestinationPort)
        }
        if target.HealthCheckHost == "" {
            return nil, fmt.Errorf("target %s is missing health_check_host", target.Name)
        }
        if target.HealthCheckPort <= 0 || target.HealthCheckPort > 65535 {
            return nil, fmt.Errorf("target %s has invalid health_check_port %d (must be 1-65535)", target.Name, target.HealthCheckPort)
        }
        
        // Validate protocol if specified
        if target.Protocol != "" && target.Protocol != "tcp" && target.Protocol != "udp" {
            return nil, fmt.Errorf("target %s has invalid protocol %s (must be 'tcp' or 'udp')", target.Name, target.Protocol)
        }

        // Validate shutdown configuration
        // Disallow using both SSH shutdown command and HTTP shutdown URL
        if strings.TrimSpace(target.ShutdownHTTPUrl) != "" && strings.TrimSpace(target.ShutdownCommand) != "" {
            return nil, fmt.Errorf("target %s: cannot define both shutdown_http_url and shutdown_command; choose one", target.Name)
        }

        // Disallow http method/ok status without URL
        if strings.TrimSpace(target.ShutdownHTTPUrl) == "" && (strings.TrimSpace(target.ShutdownHTTPMethod) != "" || target.ShutdownHTTPOKStatus != 0) {
            return nil, fmt.Errorf("target %s: shutdown_http_method and/or shutdown_http_ok_status require shutdown_http_url to be set", target.Name)
        }

        // Parse inactivity threshold if provided
        if target.InactivityThreshold != "" {
            inactivityThreshold, err := time.ParseDuration(target.InactivityThreshold)
            if err != nil {
                return nil, fmt.Errorf("invalid inactivity_threshold for target %s: %w", target.Name, err)
            }
			inactivityThresholds[target.Name] = inactivityThreshold
		}

		targetCopy := target
		targets[target.Name] = &TargetState{
			Target:       &targetCopy,
			LastActivity: time.Now(), // Initialize with current time
		}
	}

	return &ProxyConfig{
		Timeout:              timeout,
		PollInterval:         pollInterval,
		HealthCheckInterval:  healthCheckInterval,
		HealthCacheDuration:  healthCacheDuration,
		Targets:              targets,
		InactivityThresholds: inactivityThresholds,
	}, nil
}

// Simple logger implementation
type StdLogger struct{}

func (l *StdLogger) Info(msg string, args ...interface{}) {
	log.Printf("[INFO] "+msg, args...)
}

func (l *StdLogger) Error(msg string, args ...interface{}) {
	log.Printf("[ERROR] "+msg, args...)
}

// Main function
func main() {
	if len(os.Args) < 2 {
		log.Fatal("Usage: wol-proxy <config.toml>")
	}

	configFile := os.Args[1]

	// Load configuration
	config, err := LoadConfig(configFile)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize dependencies
	logger := &StdLogger{}
	healthChecker := NewTCPHealthChecker(logger)
	wolSender := NewUDPWOLSender(logger)
	sshExecutor := NewDefaultSSHExecutor(logger)

	// Create proxy service
	proxy := NewProxyService(config, healthChecker, wolSender, sshExecutor, logger)

	// Start the service
	ctx := context.Background()
	if err := proxy.Start(ctx); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}
