package main

import (
	"fmt"
	"net"
	"os"
    "time"
)

type Timeout struct {
    tot time.Duration
}

func (t Timeout) start(ch chan string) {
    time.Sleep(t.tot)
    ch <- "timeout"
}

func readudp(conn *net.UDPConn, ch chan string) {

    var data [512]byte
    _, addr, err := conn.ReadFromUDP(data[0:])
    if err != nil {
        fmt.Println(err)
        ch <- "readerr"
        return
    }

	// Print the data read from the connection to the terminal
	fmt.Print("> ", addr, " ", string(data[0:]))
    ch <- "read"
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
		fmt.Println(err)
		os.Exit(1)
	}

	// Send a message to the server
	_, err = conn.WriteToUDP([]byte("Hello UDP Server\n"), udpRemoteAddr)
	fmt.Println("send...")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

    ch := make(chan string)
    to := Timeout{5 * time.Second}
    go readudp(conn, ch)
    go to.start(ch)
    <-ch
}
