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

type TimeoutControl struct {
    name string
    avgto time.Duration
    fudge time.Duration
}

type TimeoutInfo struct {
    eta time.Time
    alive bool
}

type Timeout struct {
    avgto_ time.Duration
    fudge_ time.Duration
    impl_ *time.Timer
    alive_ bool
    eta_ time.Time
    callback_ TimeoutCallback

    control chan TimeoutControl
    info chan TimeoutInfo
}

type TimeoutCallback func (*Timeout)

func NewTimeout(avgto time.Duration, fudge time.Duration, callback TimeoutCallback) (*Timeout) {
    timeout := Timeout{avgto, fudge, nil, false, time.Now(), callback, make(chan TimeoutControl), make(chan TimeoutInfo)}
    go timeout._handler()
    defer timeout.restart()
    return &timeout
}

func NewTimeout2(avgto time.Duration, fudge time.Duration, cbch chan Event, msg string) (*Timeout) {
    cb := func(_ *Timeout) {
        cbch <- Event{msg}
    }
    return NewTimeout(avgto, fudge, cb)
}

func (timeout *Timeout) _handler() {
    // Only this goroutine, _handle_command and _restart can touch Timeout private data
loop:
    for {
        select {
        case cmd := <- timeout.control:
           if !timeout._handle_command(cmd) {
                break loop
            }
        case timeout.info <- TimeoutInfo{timeout.eta_, timeout.alive_}:
            continue
        }
    }
}

func (timeout *Timeout) _handle_command(cmd TimeoutControl) (bool) {
    switch cmd.name {
    case "refresh":
        // exists just to make select generate a new TimeoutInfo
        break
    case "reset":
        timeout.avgto_ = cmd.avgto
        timeout.fudge_ = cmd.fudge
        timeout._restart()
    case "restart":
        timeout._restart()
    case "trigger":
        timeout.alive_ = false
        // callback must be in a goroutine because it may reconfigure the Timeout itself
        // which would cause a deadlock due to unbuffered control channel, if called in
        // the timer goroutine context
        go timeout.callback_(timeout)
    case "stop":
        timeout.impl_.Stop()
        timeout.alive_ = false
    case "free":
        timeout.impl_.Stop()
        timeout.alive_ = false
        return false
    }
    return true
}

func (timeout *Timeout) _restart() {
    if timeout.impl_ != nil {
        timeout.impl_.Stop()
    }

    relative_eta := timeout.avgto_ + 2 * timeout.fudge_ * time.Duration(rand.Float32() - 0.5)
    timeout.eta_ = time.Now().Add(relative_eta)
    timeout.alive_ = true 

    timeout.impl_ = time.AfterFunc(relative_eta, func() {
        // goroutine context; make sure it goes through the control channel
        timeout.control <- TimeoutControl{"trigger", 0, 0}
    })
}

// public methods for Timeout

func (timeout *Timeout) stop() {
    timeout.control <- TimeoutControl{"stop", 0, 0}
}

func (timeout *Timeout) free() {
    timeout.control <- TimeoutControl{"free", 0, 0}
}

func (timeout *Timeout) restart() {
    timeout.control <- TimeoutControl{"restart", 0, 0}
}

func (timeout *Timeout) reset(avgto time.Duration, fudge time.Duration) {
    timeout.control <- TimeoutControl{"reset", avgto, fudge}
}

func (timeout *Timeout) alive() (bool) {
    timeout.control <- TimeoutControl{"refresh", 0, 0}
    info := <- timeout.info
    return info.alive
}

func (timeout *Timeout) remaining() (time.Duration) {
    timeout.control <- TimeoutControl{"refresh", 0, 0}
    info := <- timeout.info
    if !info.alive {
        return 0
    }
    return info.eta.Sub(time.Now()) 
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

// VMonitor shared global state

type VMonitor struct {
    our_challenge_ [2]string
    their_challenge_ [2]string
    peer_addr_ [2]*net.UDPAddr

    our_challenge_control chan VMonitorChallenge
    their_challenge_control chan VMonitorChallenge
    peer_addr_control chan VMonitorPeer
    data_channel chan VMonitorData
    data_ch_ping chan struct{}
}

type VMonitorData struct {
    our_challenge [2]string
    their_challenge [2]string
    peer_addr [2]*net.UDPAddr
}

type VMonitorChallenge struct {
    link int
    challenge string
}

type VMonitorPeer struct {
    link int
    addr *net.UDPAddr
}

func NewVMonitor() (*VMonitor) {
    global := VMonitor{
                    [2]string{"None", "None"},
                    [2]string{"None", "None"},
                    [2]*net.UDPAddr{nil, nil},
                    make(chan VMonitorChallenge),
                    make(chan VMonitorChallenge),
                    make(chan VMonitorPeer),
                    make(chan VMonitorData),
                    make(chan struct{}),
    }

    go global.handler()
    return &global
}

// Only this goroutine touches private data

func (global *VMonitor) handler() {
    for {
        select {
        case <-global.data_ch_ping:
            // refresh VMonitorData
            break
        case global.data_channel <- VMonitorData{global.our_challenge_, global.their_challenge_, global.peer_addr_}:
            break
        case oc := <- global.our_challenge_control:
            global.our_challenge_[oc.link] = oc.challenge       
        case tc := <- global.their_challenge_control:
            global.their_challenge_[tc.link] = tc.challenge       
        case pa := <- global.peer_addr_control:
            global.peer_addr_[pa.link] = pa.addr
        }
    }
}

// public methods to manipulate shared global state

func (global *VMonitor) our_challenge(link int) (string) {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).our_challenge[link-1]
}

func (global *VMonitor) their_challenge(link int) (string) {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).their_challenge[link-1]
}

func (global *VMonitor) peer_addr(link int) (*net.UDPAddr) {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).peer_addr[link-1]
}

func (global *VMonitor) our_challenge_set(link int, challenge string) {
    global.our_challenge_control <- VMonitorChallenge{link-1, challenge}
}

func (global *VMonitor) their_challenge_set(link int, challenge string) {
    global.their_challenge_control <- VMonitorChallenge{link-1, challenge}
}

func (global *VMonitor) peer_addr_set(link int, addr *net.UDPAddr) {
    global.peer_addr_control <- VMonitorPeer{link-1, addr}
}

// UDP packet receiver

func eq_addr(addr1 *net.UDPAddr, addr2 *net.UDPAddr) (bool) {
    return addr1.Port == addr2.Port && addr1.IP.Equal(addr2.IP)
}

func recvudp(global *VMonitor, persona string, conn *net.UDPConn, link int, secret []byte,
             feedback chan Event, msg_goodpacket string, msg_goodresponse string) {
    data := make([]byte, 1500, 1500)

    for {
        length, addr, err := conn.ReadFromUDP(data[0:])
        if err != nil {
            log.Fatal(err)
        }

        log.Print(link, ">")
        challenge, response := parse_packet(link, secret, data[0:length])
        if challenge == "" || response == "" {
            continue
        }

        peer_addr := global.peer_addr(link)

        if persona == "server" {
            if peer_addr == nil || !eq_addr(peer_addr, addr) {
                global.peer_addr_set(link, addr)
                log.Print(link, "> Detected new peer addr: ", addr)
            }
        }

        // packet received and valid, up to this point. Now, check challenges

        global.their_challenge_set(link, challenge)
        our_challenge := global.our_challenge(link)

        msg := msg_goodpacket

        if our_challenge == "None" {
            log.Print(link, "> Not evaluating response")
        } else if response == our_challenge {
            log.Print(link, "> Good response")
            msg = msg_goodresponse
            global.our_challenge_set(link, "None")
        } else if response == "None" {
            log.Print(link, "> Null response (exchange incomplete)")
        } else {
            log.Print(link, "> Wrong response")
        }

        feedback <- Event{msg}
    }
}

// UDP packet sender

func sendudp(global *VMonitor, link int, secret []byte, conn *net.UDPConn, addr *net.UDPAddr) {
    if global.our_challenge(link) == "None" {
        global.our_challenge_set(link, fmt.Sprintf("%x", rand.Int32()))
    }
    packet := gen_packet(link, secret, global.our_challenge(link), global.their_challenge(link)) 

    _, err := conn.WriteToUDP(packet, addr)
    if err != nil {
        log.Print(err) // non-fatal
    } else {
        log.Print("Link ", link, " sent ", string(packet))
    }
}

func send_ping(global *VMonitor, link int, conn *net.UDPConn, secret []byte) {
    addr := global.peer_addr(link)
    if addr == nil {
        log.Print("Link ", link, ": peer address still unknown")
        return
    }
    sendudp(global, link, secret, conn, addr)
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
    log.SetFlags(log.Flags() &^ (log.Ldate | log.Ltime))

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

    global := NewVMonitor()

    if persona == "client" {
        global.peer_addr_set(1, remoteaddr1)
        global.peer_addr_set(2, remoteaddr2)
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

    // using a goroutine this since ch is unbuffered
    go func() { ch <- Event{"start"} }()

    secret := []byte(cfgs["secret"])

    send_to := NewTimeout(secs(cfgi["pingavg"]), secs(cfgi["pingvar"]), func (to *Timeout) {
        // a timeout handler runs in goroutine context
        send_ping(global, 1, socket1, secret)
        send_ping(global, 2, socket2, secret)
        // try to log after packets have been sent and timer has been restarted
        go func() { ch <- Event{"send"} }()
        to.restart()
    });

    // timeouts for packet reception
    to1 := NewTimeout2(secs(cfgi["timeout"]), 0, ch, "timeout1")
    to2 := NewTimeout2(secs(cfgi["timeout"]), 0, ch, "timeout2")

    // timeouts for challenge response
    cto1 := NewTimeout2(secs(cfgi["ctimeout"]), 0, ch, "ctimeout1")
    cto2 := NewTimeout2(secs(cfgi["ctimeout"]), 0, ch, "ctimeout2")

    // heartbeats
    heartbeat_timer := NewTimeout2(secs(cfgi["heartbeat"]), 0, ch, "heartbeat")
    var hard_heartbeat_timer *Timeout = nil
    if cfgi["hard_heartbeat"] > 0 {
        hard_heartbeat_timer = NewTimeout2(secs(cfgi["hard_heartbeat"]), 0, ch, "hard_heartbeat")
    }

    // state change hysteresis
    hysteresis_timer := NewTimeout2(secs(cfgi["initial_hysteresis"]), 0, ch, "hysteresis")

    // goroutines that receive beacon packets from remote side
    go recvudp(global, persona, socket1, 1, secret, ch, "recv1", "Recv1")
    go recvudp(global, persona, socket2, 2, secret, ch, "recv2", "Recv2")

    var current_state = "undefined"

    // Main event loop

    for event := range ch {
        // handle these first so the log reflects the updated link timeouts
        switch event.name {
            case "recv1":
                to1.restart()
            case "Recv1":
                to1.restart()
                cto1.restart()
            case "recv2":
                to2.restart()
            case "Recv2":
                to2.restart()
                cto2.restart()
        }

        log.Print("State ", current_state,
                    " to1 ", int(to1.remaining().Seconds()),
                    "/", int(cto1.remaining().Seconds()),
                    " to2 ", int(to2.remaining().Seconds()),
                    "/", int(cto2.remaining().Seconds()),
                    " hys ", int(hysteresis_timer.remaining().Seconds()),
                    " ping ", int(send_to.remaining().Seconds()),
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
            hysteresis_timer.reset(secs(cfgi["hysteresis"]), 0)
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
