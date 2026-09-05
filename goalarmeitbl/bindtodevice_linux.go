//go:build linux

package goalarmeitbl

import "syscall"

// bindToDeviceControl returns a net.ListenConfig.Control function that binds
// the socket to the given network interface via SO_BINDTODEVICE.
func bindToDeviceControl(iface string) (func(network, address string, c syscall.RawConn) error, error) {
    ctrl := func(network, address string, c syscall.RawConn) error {
        var sockerr error
        err := c.Control(func(fd uintptr) {
            sockerr = syscall.SetsockoptString(int(fd), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, iface)
        })
        if err != nil {
            return err
        }
        return sockerr
    }
    return ctrl, nil
}
