package main

import (
	"fmt"
	"net"
	"os"
    "time"
    "log"
)

type Event struct {
    name string
    payload []byte
}

type Timeout struct {
    to time.Duration
    impl *time.Timer
    ch chan Event
    msg string
}

func NewTimeout(to time.Duration, ch chan Event, msg string) (Timeout) {
    timeout := Timeout{to, nil, ch, msg}
    timeout.start()
    return timeout
}

func (timeout Timeout) start() {
    timeout.impl = time.AfterFunc(timeout.to, func() {
        timeout.ch <- Event{timeout.msg, nil}
    })
}

func (timeout Timeout) stop() (bool) {
    return timeout.impl.Stop()
}

func (timeout Timeout) restart() (bool) {
    return timeout.impl.Reset(timeout.to)
}

func (timeout Timeout) reset(to time.Duration) (bool) {
    timeout.to = to
    return timeout.restart()
}

func readudp(conn *net.UDPConn, ch chan Event, evtname string) {
    for {
        data := make([]byte, 512, 512)
        n, _, err := conn.ReadFromUDP(data[0:])
        if err != nil {
            log.Fatal(err)
        }
        ch <- Event{evtname, data[0:n]}
    }
}

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Please provide host:port to bind, and host:port to connect to")
		os.Exit(1)
	}

	// Resolve the string address to a UDP address
	udpLocalAddr, err := net.ResolveUDPAddr("udp", os.Args[1])

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	udpRemoteAddr, err := net.ResolveUDPAddr("udp", os.Args[2])

	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

    // Bind to UDP
	conn, err := net.ListenUDP("udp", udpLocalAddr)

	if err != nil {
		fmt.Fatal(err)
	}

	// Send a message to the server
	_, err = conn.WriteToUDP([]byte("Hello UDP Server\n"), udpRemoteAddr)
	fmt.Println("send...")
	if err != nil {
        log.Print(err)
	}

    ch := make(chan Event)
    NewTimeout(5 * time.Second, ch, "timeout1")
    go readudp(conn, ch, "read1")
    event := <-ch
	fmt.Println(event)
}
