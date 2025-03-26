package main

import (
    "fmt"
    "net"
    "os"
    "time"
    "log"
    "strings"
    "strconv"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "github.com/ncruces/go-strftime"
    "math/rand/v2"
    "os/exec"
)

const link1_server = "127.0.0.1:55000"
const link2_server = "127.0.0.1:55001"
var server = []string {link1_server, link2_server}
const link1_client = "127.0.0.1:55002"
const link2_client = "127.0.0.1:55003"
var client = []string {link1_client, link2_client}

const pingavg = 20
const pingvar = 10
const timeout = 60
const ctimeout = 90
const hysteresis = 90
const initial_hysteresis = 60

const heartbeat = 3600
const hard_heartbeat = 600

const link1_link2_script = "./link1_link2_script"
const link2_script = "./link2_script"
const link1_script = "./link1_script"
const nolink_script = "./nolink_script"
var state_scripts = []string {nolink_script, link1_script, link2_script, link1_link2_script}

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

func NewTimeout(to time.Duration, ch chan Event, msg string) (*Timeout) {
    timeout := new(Timeout)
    *timeout = Timeout{to, nil, ch, msg, true, time.Now().Add(to)}

    timeout.impl = time.AfterFunc(timeout.to, func() {
        timeout.alive_ = false
        timeout.ch <- Event{timeout.msg}
    })

    return timeout
}

func (timeout *Timeout) stop() {
    timeout.impl.Stop()
    timeout.alive_ = false
}

func (timeout *Timeout) restart() {
    timeout.eta = time.Now().Add(timeout.to)
    timeout.impl.Reset(timeout.to)
    timeout.alive_ = true 
}

func (timeout *Timeout) reset(to time.Duration) {
    timeout.to = to
    timeout.restart()
}

func (timeout *Timeout) alive() (bool) {
    return timeout.alive_
}

func (timeout *Timeout) remaining() (time.Duration) {
    if !timeout.alive_ {
        return 0
    }
    return timeout.eta.Sub(time.Now()) 
}

// Packet codec

func gen_hmac(data []byte, key []byte) (string) {
    mac := hmac.New(sha256.New, key)
    mac.Write(data)
    return hex.EncodeToString(mac.Sum(nil))[0:16]
}

func gen_packet(link int, key []byte, challenge string, response string) ([]byte) {
    now := time.Now().UTC()
    our_time := strftime.Format("%Y-%m-%dT%H:%M:%S", now)
    sdata := fmt.Sprintf("%d %s %s %s ", link, our_time, challenge, response)
    data := []byte(sdata)
    hexdigest := []byte(gen_hmac(data, key))
    data = append(data, hexdigest...)
    return data
}

func parse_packet(link int, key []byte, bdata []byte) (string, string) {
    sdata := string(bdata)
    data := strings.Fields(sdata)
    if len(data) != 5 {
        log.Print(link, "> Invalid packet format ", data)
        return "", "" 
    }

    their_link := data[0]
    their_time := data[1]
    challenge := data[2]
    response := data[3]
    hmac := data[4]

    if their_link != "1" && their_link != "2" {
        log.Print(link, "> Bad link number ", their_link)
        return "", "" 
    }

    ilink, _ := strconv.Atoi(their_link)
    if ilink != link {
        log.Print(link, "> Unexpected link number ", their_link, " ours is ", link)
        return "", "" 
    }

    tmp := fmt.Sprintf("%s %s %s %s ", their_link, their_time, challenge, response)
    exp_hmac := gen_hmac([]byte(tmp), key)
    if exp_hmac != hmac {
        log.Print(link, "> Inconsistent HMAC")
        return "", "" 
    }
    
    log.Print(link, "> Received ", tmp)

    their_time_parsed, err := strftime.Parse("%Y-%m-%dT%H:%M:%S", their_time)
    if err != nil {
        log.Print(link, "> Date parsing error: ", err)
        return "", "" 
    }

    now := time.Now().UTC()
    diff := their_time_parsed.Sub(now)
    if diff.Seconds() > 120 {
        log.Print(link, "> Skewed date/time, here ", now, " theirs ", their_time)
        return "", "" 
    }

    return challenge, response
}

// VMonitor global state

var our_challenge = []string {"None", "None"}
var their_challenge = []string {"None", "None"}
var peer_addrs = []*net.UDPAddr {nil, nil}
var persona = "client"

// UDP packet receiver

func eq_addr(addr1 *net.UDPAddr, addr2 *net.UDPAddr) (bool) {
    return addr1.Port == addr2.Port && addr1.IP.Equal(addr2.IP)
}

func readudp(conn *net.UDPConn, link int, to *Timeout, cto *Timeout, ch chan Event, msg string) {
    for {
        data := make([]byte, 1500, 1500)
        length, addr, err := conn.ReadFromUDP(data[0:])
        if err != nil {
            log.Fatal(err)
        }
        log.Print(msg)
        challenge, response := parse_packet(link, []byte(secret), data[0:length])
        if challenge == "" || response == "" {
            continue
        }

        if persona == "server" {
            if peer_addrs[link-1] == nil || !eq_addr(peer_addrs[link-1], addr) {
                peer_addrs[link-1] = addr
                log.Print(link, "> Detected new peer addr: ", addr)
            }
        }

        to.restart()
        their_challenge[link-1] = challenge

        if our_challenge[link-1] == "None" {
            log.Print(link, "> Not evaluating response")
        } else if response == our_challenge[link-1] {
            log.Print(link, "> Good response")
            cto.restart()
            our_challenge[link-1] = "None"
        } else if response == "None" {
            log.Print(link, "> Null response (exchange incomplete)")
        } else {
            log.Print(link, "> Wrong response")
        }

        ch <- Event{msg}
    }
}

// UDP packet sender

func sendudp(link int, conn *net.UDPConn) {

    var nil_log = false

    for {
        addr := peer_addrs[link-1]

        if addr != nil {
            nil_log = false
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

        } else if !nil_log {
            log.Print("Link  ", link, ": peer address still unknown")
            nil_log = true
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
    persona = os.Args[1]

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

    if persona == "client" {
        peer_addrs[0] = remoteaddr1
        peer_addrs[1] = remoteaddr2
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
    go sendudp(1, socket1)
    go sendudp(2, socket2)

    // timeouts for packet reception
    to1 := NewTimeout(timeout * time.Second, ch, "timeout1")
    to2 := NewTimeout(timeout * time.Second, ch, "timeout2")

    // timeouts for challenge response
    cto1 := NewTimeout(ctimeout * time.Second, ch, "ctimeout1")
    cto2 := NewTimeout(ctimeout * time.Second, ch, "ctimeout2")

    // heartbeats
    heartbeat_timer := NewTimeout(heartbeat * time.Second, ch, "heartbeat")
    var hard_heartbeat_timer *Timeout = nil
    if hard_heartbeat > 0 {
        hard_heartbeat_timer = NewTimeout(hard_heartbeat * time.Second, ch, "hard_heartbeat")
    }

    // state change hysteresis
    hysteresis_timer := NewTimeout(initial_hysteresis * time.Second, ch, "hysteresis")

    // goroutines that receive beacon packets from remote side
    go readudp(socket1, 1, to1, cto1, ch, "recv1")
    go readudp(socket2, 2, to2, cto2, ch, "recv2")

    var current_state = "undefined"

    // Main event loop

    for {
        event := <-ch;
        log.Print("State ", current_state,
                    " to1 ", int(to1.remaining().Seconds()),
                    "/", int(cto1.remaining().Seconds()),
                    " to2 ", int(to2.remaining().Seconds()),
                    "/", int(cto2.remaining().Seconds()),
                    " hys ", int(hysteresis_timer.remaining().Seconds()),
                    " event ", event.name)

        heartbeat_timer.restart()

        if hysteresis_timer.alive() {
            continue
        }

        // determine whether links are up or down based on packet recv timeouts
        link1_up := to1.alive() && cto1.alive()
        link2_up := to2.alive() && cto2.alive()

        i := 0
        if link1_up {
            i += 1
        }
        if link2_up {
            i += 2
        }

        new_state := []string{"NOLINK", "LINK1", "LINK2", "LINK1_LINK2"}[i]
        new_state_script := state_scripts[i]

        if new_state != current_state {
            current_state = new_state
            log.Print("New state: ", current_state)
        } else if hard_heartbeat_timer != nil && !hard_heartbeat_timer.alive() {
            log.Print("Reapply state: ", current_state)
            hard_heartbeat_timer.restart()
        } else {
            continue
        }

        if new_state_script != "" {
            log.Print("> Running state script")
            cmd := exec.Command("/bin/bash", "-c", new_state_script) 
            if err := cmd.Run(); err != nil {
                log.Print("> Script execution error: ", err)
            }
        } else {
            log.Print("> No script configured for state")
        }

        hysteresis_timer.reset(hysteresis * time.Second)
    }
}
