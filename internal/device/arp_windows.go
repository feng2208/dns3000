package device

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIpNetTable = iphlpapi.NewProc("GetIpNetTable")
)

const (
	MAXLEN_PHYSADDR = 8
)

type MIB_IPNETROW struct {
	Index       uint32
	PhysAddrLen uint32
	PhysAddr    [MAXLEN_PHYSADDR]byte
	Addr        uint32
	Type        uint32
}

func refreshARPTable() error {
	// Initial buffer size
	var size uint32 = 0

	// First call to get size
	r1, _, _ := procGetIpNetTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		0,
	)

	// ERROR_INSUFFICIENT_BUFFER = 122
	if r1 != 122 && r1 != 0 {
		return fmt.Errorf("GetIpNetTable failed: %d", r1)
	}

	if size == 0 {
		return nil
	}

	buf := make([]byte, size)
	r2, _, _ := procGetIpNetTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0,
	)
	if r2 != 0 {
		return fmt.Errorf("GetIpNetTable failed: %d", r2)
	}

	// Parse Table
	// struct MIB_IPNETTABLE { DWORD dwNumEntries; MIB_IPNETROW table[ANY_SIZE]; }
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := uint32(unsafe.Sizeof(MIB_IPNETROW{}))

	offset := uint32(4)

	for i := uint32(0); i < numEntries; i++ {
		// Safety check
		if offset+rowSize > uint32(len(buf)) {
			break
		}

		// Read Row
		// Custom parsing to avoid struct alignment issues if any, implies unsafe cast usually fine here
		// but explicit reading is safer?
		// Let's use unsafe cast for convenience if struct matches strict layout.
		// Go struct alignment might differ. Manual read matches C layout better.

		// MIB_IPNETROW
		// Index 0-4
		// PhysAddrLen 4-8
		// PhysAddr 8-16
		// Addr 16-20
		// Type 20-24

		physAddrLen := binary.LittleEndian.Uint32(buf[offset+4 : offset+8])
		if physAddrLen > MAXLEN_PHYSADDR {
			physAddrLen = MAXLEN_PHYSADDR
		}

		physAddr := buf[offset+8 : offset+8+physAddrLen]
		if len(physAddr) == 6 {
			mac := net.HardwareAddr(physAddr).String()

			addrVal := binary.LittleEndian.Uint32(buf[offset+16 : offset+20])
			// IPv4 address in network byte order? or host? Windows struct usually has it as DWORD.
			// It is usually Network byte order.
			ip := net.IPv4(byte(addrVal), byte(addrVal>>8), byte(addrVal>>16), byte(addrVal>>24))

			// Type: 4 = Dynamic, 3 = Static. 2 = Invalid.
			typeVal := binary.LittleEndian.Uint32(buf[offset+20 : offset+24])
			if typeVal != 2 { // Not Invalid
				storeARPEntry(ip.String(), mac)
			}
		}

		offset += rowSize
	}

	return nil
}
