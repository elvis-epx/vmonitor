package main

import (
    "fmt"
    "net"
    "os"
    "time"
    "log"
    "math"
    "strings"
    "strconv"
    "sync"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
    "math/rand/v2"
    "os/exec"
    "gopkg.in/ini.v1"
    "github.com/ncruces/go-strftime"
)

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
    mu sync.Mutex
}

// TODO try to replace the mutex with something more idiomatic
// and still allows for alive() and remaining() methods

func NewTimeout(to time.Duration, ch chan Event, msg string) (*Timeout) {
    timeout := new(Timeout)
    var mutex sync.Mutex
    *timeout = Timeout{to, nil, ch, msg, true, time.Now().Add(to), mutex}

    timeout.impl = time.AfterFunc(timeout.to, func() {
        timeout.alive_ = false
        timeout.ch <- Event{timeout.msg}
    })

    return timeout
}

func (timeout *Timeout) stop() {
    timeout.mu.Lock()
    defer timeout.mu.Unlock()

    timeout.impl.Stop()
    timeout.alive_ = false
}

func (timeout *Timeout) restart() {
    timeout.mu.Lock()
    defer timeout.mu.Unlock()

    timeout._restart()
}

func (timeout *Timeout) _restart() {
    timeout.eta = time.Now().Add(timeout.to)
    timeout.impl.Reset(timeout.to)
    timeout.alive_ = true 
}

func (timeout *Timeout) reset(to time.Duration) {
    timeout.mu.Lock()
    defer timeout.mu.Unlock()

    timeout.to = to
    timeout._restart()
}

func (timeout *Timeout) alive() (bool) {
    timeout.mu.Lock()
    defer timeout.mu.Unlock()

    return timeout.alive_
}

func (timeout *Timeout) remaining() (time.Duration) {
    timeout.mu.Lock()
    defer timeout.mu.Unlock()

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
    if math.Abs(diff.Seconds()) > 120 {
        log.Print(link, "> Skewed date/time, here ", now, " theirs ", their_time)
        return "", "" 
    }

    return challenge, response
}

// VMonitor global state

var our_challenge = []string {"None", "None"}
var their_challenge = []string {"None", "None"}
var peer_addrs = []*net.UDPAddr {nil, nil}

// UDP packet receiver

func eq_addr(addr1 *net.UDPAddr, addr2 *net.UDPAddr) (bool) {
    return addr1.Port == addr2.Port && addr1.IP.Equal(addr2.IP)
}

func readudp(persona string, conn *net.UDPConn, link int, secret []byte, to *Timeout, cto *Timeout, ch chan Event, msg string) {
    data := make([]byte, 1500, 1500)

    for {
        length, addr, err := conn.ReadFromUDP(data[0:])
        if err != nil {
            log.Fatal(err)
        }

        log.Print(msg)
        challenge, response := parse_packet(link, secret, data[0:length])
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

func sendudp(link int, secret []byte, pingavg int, pingvar int, conn *net.UDPConn) {

    var nil_log = false

    for {
        addr := peer_addrs[link-1]

        if addr != nil {
            nil_log = false
            if our_challenge[link-1] == "None" {
                our_challenge[link-1] = fmt.Sprintf("%x", rand.Int32())
            }
            packet := gen_packet(link, secret, our_challenge[link-1], their_challenge[link-1]) 

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

        sleep := float32(pingavg) + 2.0 * float32(pingvar) * (rand.Float32() - 0.5)
        time.Sleep(time.Duration(sleep * 1000) * time.Millisecond) 
    }
}

// Misc

func secs(t int) (time.Duration) {
    return time.Duration(t) * time.Second
}

// Config parsing

var list_cfgss = []string{"link1_server", "link2_server", "link1_client", "link2_client", "secret",
                            "link1_script", "link2_script", "link1_link2_script", "nolink_script"}
var list_cfgip = []string{"pingavg", "pingvar", "timeout", "ctimeout", "heartbeat"}
var list_cfgi = []string{"hysteresis", "initial_hysteresis", "hard_heartbeat"}

func parse(cfgfile string) (string, map[string]string, map[string]int) {

    cfgs := make(map[string]string)
    cfgi := make(map[string]int)

    inidata, err := ini.Load(os.Args[1])
    if err != nil {
        return "Failed to open or parse config file", cfgs, cfgi
    }

    config, err := inidata.GetSection("vmonitor")
    if err != nil {
        return "Config file has no [vmonitor] section", cfgs, cfgi
    }

    for _, k:= range list_cfgss {
        if !config.Haskey(k) {
            return "Config file is missing item: " + k, cfgs, cfgi
        }
        v := config.Key(k).String()
        if v == "" {
            return "Config file has empty item: " + k, cfgs, cfgi
        }
        cfgs[k] = v
    }

    for _, k:= range list_cfgi {
        if !config.Haskey(k) {
            return "Config file is missing item: " + k, cfgs, cfgi
        }
        v, err := config.Key(k).Int()
        if err != nil || v < 0 {
            return "Config file has invalid int: " + k, cfgs, cfgi
        }
        cfgi[k] = v
    }

    for _, k:= range list_cfgip {
        if !config.Haskey(k) {
            return "Config file is missing item: " + k, cfgs, cfgi
        }
        v, err := config.Key(k).Int()
        if err != nil || v <= 0 {
            return "Config file has invalid int: " + k, cfgs, cfgi
        }
        cfgi[k] = v
    }

    if len(cfgs["secret"]) < 10 {
        return "Secret key must have at least 10 chars", cfgs, cfgi
    }

    if cfgi["pingavg"] <= cfgi["pingvar"] {
        return "pingavg must be larger than pingvar", cfgs, cfgi
    }

    if (cfgi["pingavg"] + cfgi["pingvar"] + 1) >= cfgi["timeout"] {
        return "pingavg + pingvar + 1 should be less than timeout", cfgs, cfgi
    }

    if cfgi["ctimeout"] <= cfgi["timeout"] {
        return "ctimeout should be bigger than timeout", cfgs, cfgi
    }
    
    if cfgi["hysteresis"] <= cfgi["timeout"] {
        return "hysteresis should be bigger than timeout", cfgs, cfgi
    }


    if cfgs["link1_server"] == cfgs["link2_server"] ||
            cfgs["link1_client"] == cfgs["link2_client"] ||
            cfgs["link1_client"] == cfgs["link1_server"] ||
            cfgs["link1_client"] == cfgs["link2_server"] ||
            cfgs["link2_client"] == cfgs["link1_server"] ||
            cfgs["link2_client"] == cfgs["link2_server"] {
        return "All four link addresses must be different", cfgs, cfgi
    }
    
    return "", cfgs, cfgi
}

// Main function

func main() {
    if len(os.Args) < 3 || (os.Args[2] != "client" && os.Args[2] != "server") {
        log.Fatal("Usage: vmonitor <config file> <client|server>")
    }

    parseerr, cfgs, cfgi := parse(os.Args[1])
    if parseerr != "" {
        log.Fatal(parseerr)
    }
    persona := os.Args[2]

    var state_scripts = []string {cfgs["nolink_script"], cfgs["link1_script"], cfgs["link2_script"], cfgs["link1_link2_script"]}
    var states = []string{"NOLINK", "LINK1", "LINK2", "LINK1_LINK2"}
    var server = []string {cfgs["link1_server"], cfgs["link2_server"]}
    var client = []string {cfgs["link1_client"], cfgs["link2_client"]}

    var local []string
    var remote []string

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
    go sendudp(1, []byte(cfgs["secret"]), cfgi["pingavg"], cfgi["pingvar"], socket1)
    go sendudp(2, []byte(cfgs["secret"]), cfgi["pingavg"], cfgi["pingvar"], socket2)

    // timeouts for packet reception
    to1 := NewTimeout(secs(cfgi["timeout"]), ch, "timeout1")
    to2 := NewTimeout(secs(cfgi["timeout"]), ch, "timeout2")

    // timeouts for challenge response
    cto1 := NewTimeout(secs(cfgi["ctimeout"]), ch, "ctimeout1")
    cto2 := NewTimeout(secs(cfgi["ctimeout"]), ch, "ctimeout2")

    // heartbeats
    heartbeat_timer := NewTimeout(secs(cfgi["heartbeat"]), ch, "heartbeat")
    var hard_heartbeat_timer *Timeout = nil
    if cfgi["hard_heartbeat"] > 0 {
        hard_heartbeat_timer = NewTimeout(secs(cfgi["hard_heartbeat"]), ch, "hard_heartbeat")
    }

    // state change hysteresis
    hysteresis_timer := NewTimeout(secs(cfgi["initial_hysteresis"]), ch, "hysteresis")

    // goroutines that receive beacon packets from remote side
    go readudp(persona, socket1, 1, []byte(cfgs["secret"]), to1, cto1, ch, "recv1")
    go readudp(persona, socket2, 2, []byte(cfgs["secret"]), to2, cto2, ch, "recv2")

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

        new_state := states[i]
        new_state_script := state_scripts[i]

        if new_state != current_state {
            current_state = new_state
            log.Print("New state: ", current_state)
            hysteresis_timer.reset(secs(cfgi["hysteresis"]))
        } else if hard_heartbeat_timer != nil && !hard_heartbeat_timer.alive() {
            log.Print("Reapply state: ", current_state)
        } else {
            continue
        }

        if new_state_script != "None" {
            log.Print("> Running state script ", new_state_script)
            cmd := exec.Command("/bin/bash", "-c", new_state_script) 
            if err := cmd.Run(); err != nil {
                log.Print("> Script execution error: ", err)
            }
        } else {
            log.Print("> No script configured for state")
        }

        if hard_heartbeat_timer != nil {
            hard_heartbeat_timer.restart()
        }
    }
}
