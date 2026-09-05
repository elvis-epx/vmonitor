//go:build !linux

package goalarmeitbl

import (
    "fmt"
    "syscall"
)

// bindToDeviceControl: SO_BINDTODEVICE is Linux-specific, so binding to a
// network interface is not supported on this platform.
func bindToDeviceControl(iface string) (func(network, address string, c syscall.RawConn) error, error) {
    return nil, fmt.Errorf("binding to network interface %q is not supported on this platform", iface)
}
