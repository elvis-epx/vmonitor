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
    . "epxx.co/vmonitor/goalarmeitbl"
)

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

func parse_packet(link int, key []byte, bdata []byte, loglevel int) (string, string) {
    sdata := string(bdata)
    data := strings.Fields(sdata)
    if len(data) != 5 {
        if loglevel >= 3 {
            log.Print(link, "> Invalid packet format ", data)
        }
        return "", "" 
    }

    their_link := data[0]
    their_time := data[1]
    challenge := data[2]
    response := data[3]
    hmac := data[4]

    tmp := fmt.Sprintf("%s %s %s %s ", their_link, their_time, challenge, response)
    exp_hmac := gen_hmac([]byte(tmp), key)
    if exp_hmac != hmac {
        if loglevel >= 3 {
            log.Print(link, "> Inconsistent HMAC")
        }
        return "", "" 
    }
    
    if loglevel >= 3 {
        log.Print(link, "> Received ", tmp)
    }

    if their_link != "1" && their_link != "2" {
        if loglevel >= 0 {
            log.Print(link, "> Bad link number ", their_link)
        }
        return "", "" 
    }

    ilink, _ := strconv.Atoi(their_link)
    if ilink != link {
        if loglevel >= 0 {
            log.Print(link, "> Unexpected link number ", their_link, " ours is ", link)
        }
        return "", "" 
    }

    their_time_parsed, err := strftime.Parse("%Y-%m-%dT%H:%M:%S", their_time)
    if err != nil {
        if loglevel >= 0 {
            log.Print(link, "> Date parsing error: ", err)
        }
        return "", "" 
    }

    now := time.Now().UTC()
    diff := their_time_parsed.Sub(now)
    if math.Abs(diff.Seconds()) > 120 {
        if loglevel >= 0 {
            log.Print(link, "> Skewed date/time, here ", now, " theirs ", their_time)
        }
        return "", "" 
    }

    return challenge, response
}

// VMonitor shared global state

type VMonitor struct {
    our_challenge_ [2]string
    our_challenge_regen_ [2]bool
    their_challenge_ [2]string
    peer_addr_ [2]string

    our_challenge_control chan VMonitorChallenge
    their_challenge_control chan VMonitorChallenge
    our_challenge_regen_control chan VMonitorRegen
    peer_addr_control chan VMonitorPeer
    data_channel chan VMonitorData
    data_ch_ping chan struct{}
}

type VMonitorData struct {
    our_challenge [2]string
    our_challenge_regen [2]bool
    their_challenge [2]string
    peer_addr [2]string
}

type VMonitorChallenge struct {
    link int
    challenge string
}

type VMonitorRegen struct {
    link int
    state bool
}

type VMonitorPeer struct {
    link int
    addr string
}

func NewVMonitor() (*VMonitor) {
    global := VMonitor{
                    [2]string{"None", "None"},
                    [2]bool{true, true},
                    [2]string{"None", "None"},
                    [2]string{"", ""},
                    make(chan VMonitorChallenge),
                    make(chan VMonitorChallenge),
                    make(chan VMonitorRegen),
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
        case global.data_channel <- VMonitorData{global.our_challenge_, global.our_challenge_regen_,
                                                 global.their_challenge_, global.peer_addr_}:
            break
        case oc := <- global.our_challenge_control:
            global.our_challenge_[oc.link] = oc.challenge       
        case tc := <- global.their_challenge_control:
            global.their_challenge_[tc.link] = tc.challenge       
        case ocr := <- global.our_challenge_regen_control:
            global.our_challenge_regen_[ocr.link] = ocr.state
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

func (global *VMonitor) our_challenge_regen(link int) (bool) {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).our_challenge_regen[link-1]
}

func (global *VMonitor) their_challenge(link int) (string) {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).their_challenge[link-1]
}

func (global *VMonitor) peer_addr(link int) string {
    global.data_ch_ping <- struct{}{}
    return (<-global.data_channel).peer_addr[link-1]
}

func (global *VMonitor) our_challenge_set(link int, challenge string) {
    global.our_challenge_regen_control <- VMonitorRegen{link-1, false}
    global.our_challenge_control <- VMonitorChallenge{link-1, challenge}
}

func (global *VMonitor) our_challenge_mark_regen(link int) {
    global.our_challenge_regen_control <- VMonitorRegen{link-1, true}
}

func (global *VMonitor) their_challenge_set(link int, challenge string) {
    global.their_challenge_control <- VMonitorChallenge{link-1, challenge}
}

func (global *VMonitor) peer_addr_set(link int, addr string) {
    global.peer_addr_control <- VMonitorPeer{link-1, addr}
}

// Incoming UDP packet handler

func recvudp(global *VMonitor, persona string, link int, secret []byte,
             packet UDPPacket,
             feedback chan Event, msg_goodpacket string, msg_goodresponse string,
             loglevel int) {

    if loglevel >= 3 {
        log.Print(link, ">")
    }
    challenge, response := parse_packet(link, secret, packet.Data, loglevel)
    if challenge == "" || response == "" {
        return
    }

    peer_addr := global.peer_addr(link)

    if persona == "server" {
        packet_addr := packet.Addr.String()
        if peer_addr == "" || peer_addr != packet_addr {
            global.peer_addr_set(link, packet_addr)
            if loglevel >= 2 {
                log.Print(link, "> Detected new peer addr: ", packet_addr)
            }
        }
    }

    // packet received and valid, up to this point. Now, check challenges

    global.their_challenge_set(link, challenge)
    our_challenge := global.our_challenge(link)

    msg := msg_goodpacket

    if response == "None" {
        if loglevel >= 3 {
            log.Print(link, "> Null response (exchange incomplete)")
        }
    } else if response == our_challenge {
        if loglevel >= 3 {
            log.Print(link, "> Good response")
        }
        msg = msg_goodresponse
        global.our_challenge_mark_regen(link)
    } else {
        if loglevel >= 3 {
            log.Printf("%d> Wrong response, expected %s, received %s", link, our_challenge, response)
        }
    }

    feedback <- Event{msg, nil}
}

// UDP packet sender

func sendudp(global *VMonitor, link int, secret []byte, conn *UDPServer, addr string, loglevel int) {
    if global.our_challenge_regen(link) {
        global.our_challenge_set(link, fmt.Sprintf("%x", rand.Int32()))
    }
    packet := gen_packet(link, secret, global.our_challenge(link), global.their_challenge(link)) 

    err := conn.Send(addr, packet)
    if err != nil {
        if loglevel >= 0 {
            log.Print(err) // non-fatal
        }
    } else {
        if loglevel >= 3 {
            log.Print("Link ", link, " sent ", string(packet))
        }
    }
}

func send_ping(global *VMonitor, link int, conn *UDPServer, secret []byte, loglevel int) {
    addr := global.peer_addr(link)
    if addr == "" {
        if loglevel >= 1 {
            log.Print("Link ", link, ": peer address still unknown")
        }
        return
    }
    sendudp(global, link, secret, conn, addr, loglevel)
}

// Misc

func secs(t int) (time.Duration) {
    return time.Duration(t) * time.Second
}

// Config parsing

// linkEndpoint is a parsed link1_server/link2_server/link1_client/link2_client
// entry: an "address:port" pair, optionally prefixed with "iface:" to request
// binding the local socket to that network interface via SO_BINDTODEVICE.
// When iface is set, the address is kept in config (e.g. for the user's own
// reference, or 0.0.0.0 when they don't care) but is not actually bound to;
// see NewUDPServerOnIface.
type linkEndpoint struct {
    iface string
    addr string
}

// parseLinkEndpoint accepts either "address:port" or "iface:address:port".
func parseLinkEndpoint(s string) (linkEndpoint, error) {
    if _, err := net.ResolveUDPAddr("udp", s); err == nil {
        return linkEndpoint{"", s}, nil
    }

    idx := strings.Index(s, ":")
    if idx < 0 {
        return linkEndpoint{}, fmt.Errorf("invalid address: %s", s)
    }
    iface, addr := s[:idx], s[idx+1:]

    if _, err := net.ResolveUDPAddr("udp", addr); err != nil {
        return linkEndpoint{}, fmt.Errorf("invalid address: %s", s)
    }

    return linkEndpoint{iface, addr}, nil
}

var list_cfgss = []string{"link1_server", "link2_server", "link1_client", "link2_client", "secret",
                            "link1_script", "link2_script", "link1_link2_script", "nolink_script"}
// must be positive
var list_cfgip = []string{"pingavg", "pingvar", "timeout", "ctimeout", "heartbeat"}
// can be zero
var list_cfgi = []string{"hysteresis", "initial_hysteresis", "debounce", "hard_heartbeat", "loglevel", "slo_pct", "slo_window"}

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
    
    if cfgi["slo_pct"] > 98 {
        return "slo_pct should be 98 or less", cfgs, cfgi
    }

    // slo_window should grow past the base "10 x pingavg" rule as slo_pct
    // approaches 100, since the EWMA needs a bigger window to stay stable
    // when there is less room (100 - slo_pct) to absorb its own noise.
    if cfgi["slo_pct"] > 0 && cfgi["slo_window"] * (100 - cfgi["slo_pct"]) <= cfgi["pingavg"] * 1000 {
        return "slo_window should be bigger than 10 x pingavg x 100 / (100 - slo_pct)", cfgs, cfgi
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

    link1_server, err := parseLinkEndpoint(cfgs["link1_server"])
    if err != nil {
        log.Fatal(err)
    }
    link2_server, err := parseLinkEndpoint(cfgs["link2_server"])
    if err != nil {
        log.Fatal(err)
    }
    link1_client, err := parseLinkEndpoint(cfgs["link1_client"])
    if err != nil {
        log.Fatal(err)
    }
    link2_client, err := parseLinkEndpoint(cfgs["link2_client"])
    if err != nil {
        log.Fatal(err)
    }

    var server = []linkEndpoint {link1_server, link2_server}
    var client = []linkEndpoint {link1_client, link2_client}

    var local []linkEndpoint
    var remote []linkEndpoint

    if persona == "client" {
        local = client
        remote = server
    } else {
        local = server
        remote = client
    }

    global := NewVMonitor()

    if persona == "client" {
        global.peer_addr_set(1, remote[0].addr)
        global.peer_addr_set(2, remote[1].addr)
    }

    server1, err := NewUDPServerOnIface(local[0].addr, local[0].iface)

    if err != nil {
        log.Fatal(err)
    }

    server2, err := NewUDPServerOnIface(local[1].addr, local[1].iface)

    if err != nil {
        log.Fatal(err)
    }

    ch := make(chan Event)

    // using a goroutine this since ch is unbuffered
    go func() { ch <- Event{"start", nil} }()

    secret := []byte(cfgs["secret"])

    // route events from UDPServer to our handler
    go func() {
        for evt := range server1.Events {
            if evt.Name != "Recv" {
                continue
            }
            packet := evt.Cargo.(UDPPacket)
            recvudp(global, persona, 1, secret, packet, ch, "recv1", "Recv1", cfgi["loglevel"])
        }
    }()
    go func() {
        for evt := range server2.Events {
            if evt.Name != "Recv" {
                continue
            }
            packet := evt.Cargo.(UDPPacket)
            recvudp(global, persona, 2, secret, packet, ch, "recv2", "Recv2", cfgi["loglevel"])
        }
    }()

    slo := float64(cfgi["slo_pct"]) / 100.0
    slomode := cfgi["slo_pct"] > 0
    slomode_server := persona == "server" && slomode

    // timeout for periodic pings
    pingavg := cfgi["pingavg"]
    pingvar := cfgi["pingvar"]
    if slomode_server {
        // In SLO mode server, this does not send packets, it only measures the time
        // during which a packet whould have been received
        pingavg = pingavg + pingvar + 1
        pingvar = 0
    }

    send1_to := NewTimeout(secs(pingavg), secs(pingvar), ch, "send1", nil)
    send2_to := NewTimeout(secs(pingavg), secs(pingvar), ch, "send2", nil)

    // timeouts for packet reception
    to1 := NewTimeout(secs(cfgi["timeout"]), 0, ch, "timeout1", nil)
    to2 := NewTimeout(secs(cfgi["timeout"]), 0, ch, "timeout2", nil)

    // timeouts for challenge response
    cto1 := NewTimeout(secs(cfgi["ctimeout"]), 0, ch, "ctimeout1", nil)
    cto2 := NewTimeout(secs(cfgi["ctimeout"]), 0, ch, "ctimeout2", nil)

    // SLIs
    sli1 := 1.0
    sli2 := 1.0
    sli_weight := 2.0 / (1.0 + float64(cfgi["slo_window"]) / float64(cfgi["pingavg"]))

    // heartbeats
    heartbeat_timer := NewTimeout(secs(cfgi["heartbeat"]), 0, ch, "heartbeat", nil)
    var hard_heartbeat_timer *Timeout = nil
    if cfgi["hard_heartbeat"] > 0 {
        hard_heartbeat_timer = NewTimeout(secs(cfgi["hard_heartbeat"]), 0, ch, "hard_heartbeat", nil)
    }

    // state change hysteresis
    hysteresis_timer := NewTimeout(secs(cfgi["initial_hysteresis"]), 0, ch, "hysteresis", nil)

    // state change delay
    var debounce_timer *Timeout = nil

    var current_state = "undefined"

    // Main event loop

    for event := range ch {
        // handle these first so the log reflects the updated link timeouts
        switch event.Name {
            case "recv1":
                to1.Restart()
                if slomode_server {
                    // in SLO mode, server only sends packets when provoked
                    send_ping(global, 1, server1, secret, cfgi["loglevel"])
                    // Discount one packet in SLI
                    sli1 = sli1 * (1.0 - sli_weight)
                    send1_to.Restart()
                }
            case "Recv1":
                to1.Restart()
                cto1.Restart()
                if slomode_server {
                    // in SLO mode, server only sends packets when provoked
                    send_ping(global, 1, server1, secret, cfgi["loglevel"])
                    // Add one packet to SLI
                    sli1 = sli1 * (1.0 - sli_weight) + 1.0 * sli_weight
                    send1_to.Restart()
                } else {
                    // Add one packet to SLI
                    // We just add because (in principle) the average was already weigthed down on send
                    sli1 = min(1.0, sli1 + 1.0 * sli_weight)
                }
            case "recv2":
                to2.Restart()
                if slomode_server {
                    send_ping(global, 2, server2, secret, cfgi["loglevel"])
                    // Discount one packet in SLI
                    sli2 = sli2 * (1.0 - sli_weight)
                    send2_to.Restart()
                }
            case "Recv2":
                to2.Restart()
                cto2.Restart()
                if slomode_server {
                    send_ping(global, 2, server2, secret, cfgi["loglevel"])
                    // Add one packet to SLI
                    sli2 = sli2 * (1.0 - sli_weight) + 1.0 * sli_weight
                    send2_to.Restart()
                } else {
                    // Add one packet to SLI
                    // We just add because (in principle) the average was already weigthed down on send
                    sli2 = min(1.0, sli2 + 1.0 * sli_weight)
                }
            case "send1":
                if slomode_server {
                    // in SLO mode, server only sends packets when provoked, not here
                    // Decay SLI anyway because a packet was expected meanwhile
                } else {
                    send_ping(global, 1, server1, secret, cfgi["loglevel"])
                }
                // Discount one packet in SLI
                sli1 = sli1 * (1.0 - sli_weight)
                send1_to.Restart()
            case "send2":
                if slomode_server {
                    // in SLO mode, server only sends packets when provoked, not here
                    // Decay SLI anyway because a packet was expected meanwhile
                } else {
                    send_ping(global, 2, server2, secret, cfgi["loglevel"])
                }
                // Discount one packet in SLI
                sli2 = sli2 * (1.0 - sli_weight)
                send2_to.Restart()
        }

        if cfgi["loglevel"] >= 3 {
            log.Print("State ", current_state,
                    " to1 ", int(to1.Remaining().Seconds()),
                    "/", int(cto1.Remaining().Seconds()),
                    " to2 ", int(to2.Remaining().Seconds()),
                    "/", int(cto2.Remaining().Seconds()),
                    " hys ", int(hysteresis_timer.Remaining().Seconds()),
                    " sli1 ", fmt.Sprintf("%.1f%%", 100 * sli1),
                    " sli2 ", fmt.Sprintf("%.1f%%", 100 * sli2),
                    " event ", event.Name)
        }

        heartbeat_timer.Restart()

        if hysteresis_timer.Alive() {
            continue
        }

        // determine whether links are up or down based on packet recv timeouts
        link1_up := to1.Alive() && cto1.Alive() && (!slomode || sli1 >= slo)
        link2_up := to2.Alive() && cto2.Alive() && (!slomode || sli2 >= slo)

        i := 0
        if link1_up {
            i += 1
        }
        if link2_up {
            i += 2
        }

        new_state := states[i]

        if new_state != current_state {
            if debounce_timer == nil {
                if cfgi["loglevel"] >= 2 {
                    log.Print("New state detected, starting debounce: ", new_state)
                }
                debounce_timer = NewTimeout(secs(cfgi["debounce"]), 0, ch, "debounce", nil)
                continue
            } else if debounce_timer.Alive() {
                if cfgi["loglevel"] >= 3 {
                    log.Print("Still in debounce for new state: ", new_state)
                }
                continue
            } else {
                debounce_timer = nil
                current_state = new_state
                if cfgi["loglevel"] >= 2 {
                    log.Print("New state applied: ", current_state)
                }
                hysteresis_timer.Reset(secs(cfgi["hysteresis"]), 0)
            }
        } else {
            debounce_timer.Free()
            debounce_timer = nil

            if hard_heartbeat_timer != nil && !hard_heartbeat_timer.Alive() {
                if cfgi["loglevel"] >= 3 {
                    log.Print("Reapply state: ", current_state)
                }
            } else {
                continue
            }
        }

        new_state_script := state_scripts[i]

        if new_state_script != "None" {
            if cfgi["loglevel"] >= 3 {
                log.Print("> Running state script ", new_state_script)
            }
            cmd := exec.Command("/bin/bash", "-c", new_state_script) 
            if err := cmd.Run(); err != nil {
                if cfgi["loglevel"] >= 0 {
                    log.Print("> Script execution error: ", err)
                }
            }
        } else {
            if cfgi["loglevel"] >= 3 {
                log.Print("> No script configured for state")
            }
        }

        if hard_heartbeat_timer != nil {
            hard_heartbeat_timer.Restart()
        }
    }
}
