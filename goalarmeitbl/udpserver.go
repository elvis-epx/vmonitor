package goalarmeitbl

import (
    "context"
    "fmt"
    "net"
    "log"
    "sync"
)

type UDPPacket struct {
    Addr *net.UDPAddr 
    Data []byte
}

type UDPServer struct {
    Events chan Event
    queue_depth int

    conn *net.UDPConn
    recv_buffer_size int

    waitgroup sync.WaitGroup
    log bool
}

func CheckUDPAddr(addr string) error {
    _, err := net.ResolveUDPAddr("udp", addr)
    return err
}

func NewUDPServer(slocaladdr string) (*UDPServer, error) {
    return NewUDPServerOnIface(slocaladdr, "")
}

// NewUDPServerOnIface behaves like NewUDPServer, but if iface is non-empty,
// the socket is bound to that network interface (e.g. "eth0") via
// SO_BINDTODEVICE. In that case the address portion of slocaladdr is not
// actually bound to (SO_BINDTODEVICE already restricts traffic to the
// interface); only its port is used, and the socket listens on the wildcard
// address. Only supported on Linux; on other platforms, passing a non-empty
// iface returns an error.
func NewUDPServerOnIface(slocaladdr string, iface string) (*UDPServer, error) {
    // FIXME allow configuration of queue depth for high-throughput applications
    // FIXME allow configuration of recv buffer size

    _, err := net.ResolveUDPAddr("udp", slocaladdr)
    if err != nil {
        return nil, err
    }

    lc := net.ListenConfig{}
    if iface != "" {
        if _, err := net.InterfaceByName(iface); err != nil {
            return nil, fmt.Errorf("network interface %q not found: %w", iface, err)
        }

        ctrl, err := bindToDeviceControl(iface)
        if err != nil {
            return nil, err
        }
        lc.Control = ctrl

        _, port, err := net.SplitHostPort(slocaladdr)
        if err != nil {
            return nil, err
        }
        slocaladdr = net.JoinHostPort("", port)
    }

    conn, err := lc.ListenPacket(context.Background(), "udp", slocaladdr)

    if err != nil {
        return nil, err
    }

    socket := conn.(*net.UDPConn)

    h := new(UDPServer)
    h.conn = socket

    h.queue_depth = 0
    h.recv_buffer_size = 1500
    h.Events = make(chan Event, h.queue_depth)

    h.waitgroup.Go(h.recv)

    if h.log { log.Printf("UDPServer %p ==================", h) }

    return h, nil
}

// Data receiving goroutine. Stopped by closure of h.conn
func (h *UDPServer) recv() {
    for {
        data := make([]byte, h.recv_buffer_size, h.recv_buffer_size)
        n, addr, err := h.conn.ReadFromUDP(data)

        if err != nil {
            // most probably, h.conn was closed
            if h.log { log.Printf("UDPServer %p: gorecv: err or stop", h) }
            h.Events <- Event{"Err", nil}
            break // exit goroutine
        }
        if h.log { log.Printf("UDPServer %p: gorecv: received %d", h, n) }
        h.Events <- Event{"Recv", UDPPacket{addr, data[:n]}}
    }

    if h.log { log.Printf("UDPServer %p: gorecv: exited", h) }
}

// UDP send does not block, so this method can be synchronous
func (h *UDPServer) Send(saddr string, data []byte) error {
    addr, err := net.ResolveUDPAddr("udp", saddr)
    if err != nil {
        return err
    }
    return h.SendA(addr, data)
}

// UDP send does not block, so this method can be synchronous
func (h *UDPServer) SendA(addr *net.UDPAddr, data []byte) error {
    n, err := h.conn.WriteToUDP(data, addr)
    if h.log { log.Printf("UDPServer %p: sent %d", h, n) }
    return err
}

// Close connection and release resources
// No events will be emitted after this call returns
func (h *UDPServer) Close() {
    if h.log { log.Printf("UDPServer %p: Closing...", h) }

    // indirectly stops recv goroutine, if running
    if h.conn != nil {
        h.conn.Close()
    }

    // To go in parallel with the events drainer
    go func() {
        h.waitgroup.Wait()     // wait for recv() to stop
        close(h.Events)        // Disengage user, as well as events drainer
    }()

    // Drains outstanding events until channel closed
    for evt := range h.Events {
        if h.log { log.Printf("UDPServer %p: drained %s", h, evt.Name) }
    }

    if h.log { log.Printf("UDPServer %p: exited -------------", h) }
}
