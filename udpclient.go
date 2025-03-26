package main

import (
	"fmt"
	"net"
	"os"
    "time"
    "log"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "github.com/ncruces/go-strftime"
    "math/rand/v2"
)

const link1_server = "127.0.0.1:55000"
const link2_server = "127.0.0.1:55001"
var server = []string {link1_server, link2_server}
const link1_client = "127.0.0.1:55002"
const link2_client = "127.0.0.1:55003"
var client = []string {link1_client, link2_client}

const pingavg = 20
const pingvar = 10
const timeout = 90
const ctimeout = 135
const hysteresis = 300
const heartbeat = 3600 // FIXME use it
const initial_hysteresis = 60

const link1_link2_script = "" // FIXME use it
const link2_script = "" // FIXME use it
const link1_script = "" // FIXME use it
const nolink_script = "" // FIXME use it

const hard_heartbeat = 0 // FIXME use it

const secret = "abracadabra"

// Implementation

// Base of "event loop"

type Event struct {
    name string
}

type Timeout struct {
    to time.Duration
    impl *time.Timer
    ch chan Event
    msg string
    alive_ bool
    eta time.Time
}

func NewTimeout(to time.Duration, ch chan Event, msg string) (Timeout) {
    timeout := Timeout{to, nil, ch, msg, true, time.Now().Add(to)}

    timeout.impl = time.AfterFunc(timeout.to, func() {
        timeout.alive_ = false
        timeout.ch <- Event{timeout.msg}
    })

    return timeout
}

func (timeout Timeout) stop() {
    timeout.impl.Stop()
    timeout.alive_ = false
}

func (timeout Timeout) restart() {
    timeout.eta = time.Now().Add(timeout.to)
    timeout.impl.Reset(timeout.to)
    timeout.alive_ = true 
}

func (timeout Timeout) reset(to time.Duration) {
    timeout.to = to
    timeout.restart()
}

func (timeout Timeout) alive() (bool) {
    return timeout.alive_
}

func (timeout Timeout) remaining() (time.Duration) {
    if !timeout.alive_ {
        return 0
    }
    return timeout.eta.Sub(time.Now()) 
}

// Packet codec

func gen_packet(link int, key []byte, challenge string, response string) ([]byte) {
    now := time.Now().UTC()
    our_time := strftime.Format("%Y-%m-%dT%H:%M:%S", now)
    sdata := fmt.Sprintf("%d %s %s %s ", link, our_time, challenge, response)
    data := []byte(sdata)
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    hexdigest := []byte(hex.EncodeToString(mac.Sum(nil)))[0:16]
    data = append(data, hexdigest...)
    return data
}

// VMonitor global state

var our_challenge = []string {"None", "None"}
var their_challenge = []string {"None", "None"}

// UDP packet receiver

func readudp(conn *net.UDPConn, link int, to *Timeout, cto *Timeout, ch chan Event, msg string) {
    for {
        data := make([]byte, 1500, 1500)
        n, _, err := conn.ReadFromUDP(data[0:])
        if err != nil {
            log.Fatal(err)
        }
        // FIXME parse packet, feed to, cto
        log.Print(n)
        ch <- Event{msg}
    }
}

// UDP packet sender

func sendudp(link int, conn *net.UDPConn, addr *net.UDPAddr) {
    for {
        if our_challenge[link-1] == "None" {
            our_challenge[link-1] = fmt.Sprintf("%x", rand.Int32())
        }
        packet := gen_packet(link, []byte(secret), our_challenge[link-1], their_challenge[link-1]) 
	    _, err := conn.WriteToUDP(packet, addr)
	    if err != nil {
            log.Print(err) // non-fatal
	    } else {
	        log.Print("Link ", link, " sent ", string(packet))
        }
        sleep := pingavg + 2 * pingvar * (rand.Float32() - 0.5)
        time.Sleep(time.Duration(sleep * 1000) * time.Millisecond) 
    }
}

func main() {
	if len(os.Args) < 2 || (os.Args[1] != "client" && os.Args[1] != "server") {
		log.Fatal("Usage: vmonitor <client|server>")
	}

    var local []string
    var remote []string
    var persona = os.Args[1]

    if persona == "client" {
        local = client
        remote = server
    } else {
        local = server
        remote = client
    }
        
	localaddr1, err := net.ResolveUDPAddr("udp", local[0])

	if err != nil {
		log.Fatal(err)
	}

	localaddr2, err := net.ResolveUDPAddr("udp", local[1])

	if err != nil {
		log.Fatal(err)
	}

	remoteaddr1, err := net.ResolveUDPAddr("udp", remote[0])

	if err != nil {
		log.Fatal(err)
	}

	remoteaddr2, err := net.ResolveUDPAddr("udp", remote[1])

	if err != nil {
		log.Fatal(err)
	}

	socket1, err := net.ListenUDP("udp", localaddr1)

	if err != nil {
		log.Fatal(err)
	}

	socket2, err := net.ListenUDP("udp", localaddr2)

	if err != nil {
		log.Fatal(err)
	}

    ch := make(chan Event)

    // standalone goroutines that send beacon packets
    go sendudp(1, socket1, remoteaddr1)
    go sendudp(2, socket2, remoteaddr2)

    // timeouts for packet reception
    to1 := NewTimeout(timeout * time.Second, ch, "timeout1")
    to2 := NewTimeout(timeout * time.Second, ch, "timeout2")

    // timeouts for challenge response
    cto1 := NewTimeout(ctimeout * time.Second, ch, "ctimeout1")
    cto2 := NewTimeout(ctimeout * time.Second, ch, "ctimeout2")

    // state change hysteresis
    hys := NewTimeout(initial_hysteresis * time.Second, ch, "hysteresis")

    // goroutines that receive beacon packets from remote side
    go readudp(socket1, 1, &to1, &cto1, ch, "recv1")
    go readudp(socket2, 2, &to2, &cto2, ch, "recv2")

    var state = "undefined"

    for {
        event := <-ch;
	    log.Print(event.name)
        log.Print("Status ", state,
                    " to1 ", int(to1.remaining().Seconds()),
                    "/", int(cto1.remaining().Seconds()),
                    " to2 ", int(to2.remaining().Seconds()),
                    "/", int(cto2.remaining().Seconds()),
                    " hys ", int(hys.remaining().Seconds()))

        // FIXME print general status
        if event.name != "hysteresis" {
            continue
        }
        hys.reset(hysteresis * time.Second)
        // FIXME event handler
    }
}
