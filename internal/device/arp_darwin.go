package device

import (
	"bufio"
	"bytes"
	"os/exec"
	"strings"
)

func refreshARPTable() error {
	// Fallback to exec for macOS as direct sysctl requires complex RouteMessage parsing
	// compliant with x/net/route which might not be available.
	// arp -an is relatively fast if done in bulk.
	cmd := exec.Command("arp", "-an")
	out, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		// ? (192.168.1.1) at 00:00:00:00:00:00 on en0 ifscope [ethernet]
		line := scanner.Text()
		parts := strings.Fields(line)

		if len(parts) >= 4 {
			// Extract IP: parts[1] is (1.2.3.4)
			ipRaw := parts[1]
			if len(ipRaw) > 2 {
				ip := ipRaw[1 : len(ipRaw)-1]
				mac := parts[3]

				if mac != "(incomplete)" {
					storeARPEntry(ip, mac)
				}
			}
		}
	}
	return nil
}
