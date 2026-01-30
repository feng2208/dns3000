package server

import (
	"fmt"
	"log"
	"strconv"

	"dns3000/internal/dns"

	d "github.com/miekg/dns"
)

func StartDNSServer(port int, handler *dns.Handler) {
	fmt.Printf("Starting DNS server on port %d\n", port)

	srv := &d.Server{Addr: ":" + strconv.Itoa(port), Net: "udp"}
	srv.Handler = handler
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Failed to set udp listener %s\n", err.Error())
	}
}
