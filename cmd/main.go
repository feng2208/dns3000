package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"dns3000/internal/config"
	"dns3000/internal/device"
	"dns3000/internal/dns"
	"dns3000/internal/logging"
	"dns3000/internal/rules"
	"dns3000/internal/server"
)

func main() {
	dataDir := flag.String("data-dir", "data", "Data directory")
	dnsPort := flag.Int("p", 53, "DNS server port")
	tlsCert := flag.String("tls-cert", "", "TLS certificate file")
	tlsKey := flag.String("tls-key", "", "TLS key file")
	dohPath := flag.String("doh-path", "/dns-query", "DoH path")
	dohPort := flag.Int("doh-port", 443, "DoH server port")
	webPort := flag.Int("web-port", 3000, "Web admin port")

	flag.Parse()

	// 1. Ensure config exists
	if err := config.GenerateTemplate(*dataDir); err != nil {
		log.Fatalf("Failed to generate config template: %v", err)
	}

	// 2. Load config
	cfg, err := config.Load(*dataDir)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// 3. Initialize Managers
	devMgr := device.NewManager(cfg)
	ruleMgr := rules.NewManager(cfg, *dataDir)
	if err := ruleMgr.Init(); err != nil {
		log.Printf("Warning: Failed to init rules: %v", err)
	}
	ruleMgr.Start()

	// Initialize Logger
	logger, err := logging.NewLogger(filepath.Join(*dataDir, "query.log"), cfg.LogCount)
	if err != nil {
		log.Fatalf("Failed to init logger: %v", err)
	}
	statsPath := filepath.Join(*dataDir, "stats.json")
	if err := logger.LoadStats(statsPath); err != nil {
		log.Printf("Warning: Failed to load stats: %v", err)
	}

	cache := dns.NewCache()

	// Parse Upstream Routes
	upstreamRoutes := cfg.ParseUpstreamRoutes()

	rewriteEngine := dns.NewRewriteEngine(cfg.Rewrites)

	dnsHandler := &dns.Handler{
		Cfg:            cfg,
		DeviceManager:  devMgr,
		RuleManager:    ruleMgr,
		Cache:          cache,
		Logger:         logger,
		UpstreamRoutes: upstreamRoutes,
		RewriteEngine:  rewriteEngine,
	}

	// 4. Start Servers
	go server.StartDNSServer(*dnsPort, dnsHandler)

	go server.StartWebServer(*webPort, cfg, logger, devMgr, dnsHandler, *dataDir)

	if *tlsCert != "" && *tlsKey != "" {
		go server.StartDoHServer(*dohPort, *tlsCert, *tlsKey, *dohPath, dnsHandler)
	}

	// Wait for interrupt
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("")
	log.Println("Shutting down...")

	// Save Logs
	logPath := filepath.Join(*dataDir, "query.log")
	if err := logger.SaveLogs(logPath); err != nil {
		log.Printf("Failed to save logs: %v", err)
	} else {
		log.Println("Logs saved.")
	}

	if err := logger.SaveStats(statsPath); err != nil {
		log.Printf("Failed to save stats: %v", err)
	} else {
		log.Println("Stats saved.")
	}
}
