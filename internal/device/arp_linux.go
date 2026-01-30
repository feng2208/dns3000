package device

import (
	"bufio"
	"os"
	"strings"
)

func refreshARPTable() error {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	// Skip header
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip := fields[0]
			// hwType := fields[1]
			flags := fields[2]
			mac := fields[3]

			// flags 0x0 means incomplete usually, 0x2 is complete
			// But simpler check: MAC not 00:00:00:00:00:00
			if flags != "0x0" && mac != "00:00:00:00:00:00" {
				storeARPEntry(ip, mac)
			}
		}
	}
	return scanner.Err()
}
