# VMonitor

VMonitor is a simple app in Go, put together to monitor network links. It is a
refactored version of a script I wrote in 2004 for a client.

It is currently suited for the following scenario: multihomed router with two redundant
network links (not necessarily of equal bandwidth), making a total
of four possible availability states: link 1 up, link 2 up, all links up,
all links down.

As the network availability changes to a new state, vmonitor runs a
user-supplied script. In this script, you can implement the routing
policy changes appropriate for the state (using iptables, iproute2, etc.)

With some work, vmonitor could be easily adapted to monitor "n" links,
and do other tricks.

## The basic algorithm

VMonitor detects that a link is good by 

a) Receiving UDP packets from the other side. This means the link is working in the
download direction.

b) Verifying the UDP packets have correct responses for the challenges we sent.
This means the link is working in the upload direction.

## Network layout

VMonitor is meant to run on the routers at both sides. Each network link is expected to
be connected to a different network interface. VMonitor binds to each interface 
using a separate socket, so it can force packets to go through a specific link.
By exchanging UDP packets with the peer, it detects whether the link is good.

In the original use case, both routers at both sides were expected to change
routing policies in tandem, in order to keep an enterprise VPN running. That's why the
config file is supposed to be the same for both client and server.

Another (perhaps more common) use case is: multihomed client, and a server running
in the cloud as "beacon" (more trustworthy than pinging google.com or gnu.org).
Only the client side should actually react to network changes. You still can use
the same config file for both sides, but supply no-op scripts for the server.

## Basic usage 

You can build it locally. For this, you need to install the Go toolchain. Another
option is to use the ready-made binaries in the folder builds/. Assuming you have
a binary in the current directory, you run it like this:

```
./vmonitor configfile client|server
```

The config file is meant to be the same for client and server. The
second CLI argument says to vmonitor if it has the 'client' or 'server'
persona. If the third optional argument is 'daemon', the script will
run in background.

Both client and server work exactly the same. The only difference is
a client may be behind a NAT router, so the server waits for client
packets in order to "learn" the true client's IP addresses.

## The config file

The supplied sample config file config.txt has some comments, so it is
pretty much self-explanatory. We will add a couple points here.

For each side and link, you need to supply a different address:port combination,
making a total of four. If only the client is multihomed, and the server
has only one IP, use different ports for the server pairs.

Each of the four entries may optionally be written as `iface:address:port`
to bind the local socket to a specific network interface via SO_BINDTODEVICE
(Linux only, usually requires root). SO_BINDTODEVICE already restricts traffic
to that interface, so the address is not actually bound to; use `0.0.0.0` when
you don't know or care about the interface's IP, e.g. `eth0:0.0.0.0:55000`.

Make sure you fill the 'secret' parameter with a unique passphrase, and keep
it secret! This is used to check packets indeed came from your VMonitor
counterpart. (The original version didn't need this feature because it 
monitored secure links.)

Another security measure is to send date/time in packets, and check them
at the other side. They should be within 120 seconds. This means machines
running VMonitor are expected to have reasonably accurate date and time
(most systems self-update with NTP these days). If, for some reason,
your router machine might have wrong date/time, change the source code
and disable the clock skew check.

In general, low values of pingavg, timeout, ctimeout and hysteresis yield
faster reactions to changes in connectivity. But frequent pings may cost you
if the links are metered and/or very slow (e.g. GPRS, satellite).

Since the "pings" are UDP packets, they may be lost even if the link is ok,
so it is recommended to keep a ratio between timeout/ctimeout and pingavg,
like 3:1. If your link is very lossy (like some wireless technologies are),
increase this ratio accordingly.

By default, a link is only considered down when packets stop arriving
altogether (see timeout/ctimeout above). If you also want vmonitor to react
to a link that is up but noticeably degraded, e.g. losing a meaningful
fraction of packets, set 'slo_pct' to the minimum percentage of successful
exchanges you are willing to tolerate, and 'slo_window' to roughly how many
seconds of history that estimate should be averaged over. Set slo_pct to 0
to disable this feature (the link is then judged by timeout/ctimeout alone,
as before). slo_pct cannot be set above 98.

slo_window needs to be picked with some care: too small a window relative
to slo_pct makes vmonitor flag a perfectly healthy link as degraded, simply
because of the noise inherent to a short moving average. As a rule of thumb:

```
slo_window >= 10 x pingavg x 100 / (100 - slo_pct)
```

For example, with pingavg = 2s and slo_pct = 90, slo_window should be at
least 200 seconds. The closer slo_pct gets to 100, the bigger slo_window
needs to be to stay stable.

Note that vmonitor is not the ideal tool to monitor ISP SLOs or test for SLOs
like 99.9%. The SLO it calculates is a rough estimate and should be used as a
rough guide to test whether the link is usable.

## More about algorithm and protocol

For each link, there is a timeout running. The initial value is the 'timeout'
parameter in config file. As soon as a valid packet arrives (on the socket related
to the link), the timeout is reset.

For each link, there is *another* timeout running, the initial value is 'ctimeout'.
For this timeout to reset, the arrived packet must contain the correct response
to our challenge (more on that later). This is a proof that the other side has 
been able to receive and interpret the packets we have sent.

If either of the timeouts is set off, the link is considered "down". As soon as
one valid packet arrives, it is considered "up". This could cause the network state
to bounce too much e.g. if the link is intermitent.

To avoid this, there is the "hysteresis" timeout. This is the minimum time
between state changes. For example, if timeout is 60s and hysteresis is 300s,
the first reaction after steady state is 60s, but the next reaction will take
300s.

There is also "debounce". This is the time counted between state change
detection and application. This is useful to e.g. wait a bit for the new state to settle.
For example, if you lose two links at the same time, they would timeout at
slightly different moments, and vmonitor may change state from LINK1\_LINK2
to LINK2 and then to NOLINK (after the hysteresis timeout), when the right move
would be to go straight to NOLINK.

The "pingvar" parameter adds a fudge factor to "pingtime", making it less
predictable and less likely to sync with other network events.

The timeout/ctimeout mechanism above is good at catching a link that goes
completely silent, but it says nothing about a link that stays "up" while
losing a troubling fraction of its packets. For that, vmonitor can keep a
moving estimate of packet delivery quality, the SLI (Service Level
Indicator), and treat the link as down when the SLI falls below a target,
the SLO (Service Level Objective), configured as 'slo_pct'.

The SLI is an exponentially-weighted moving average: every expected packet
exchange nudges it up (success) or down (loss/timeout), with weight

```
weight = 2 / (1 + slo_window / pingavg)
```

so 'slo_window' roughly controls how many seconds of history feed into the
estimate -- a small slo_window reacts fast but is noisy, a big slo_window is
smooth but slower to notice real degradation. See 'The config file' section
above for the rule of thumb relating slo_window to slo_pct.

The packet format is a human-readable message consisting of: link number,
date/time, challenge, response, truncated HMAC.

The link number allows VMonitor to check the packet came from the expected
counterpart socket.

The date/time helps to avoid replay attacks (where an old valid message
is resent to fool VMonitor). Currently the accepted clock skew is 2 minutes.

The challenge is a random hex number. The counterpart is expected to send
the same number in the response field of a future packet. This is a proof
the counterpart is listening to our packets. (Otherwise, if the packet
traffic was blocked in only one direction, client and server would diverge
about the link status.)
 
Once the response acknowledges the challenge, a new challenge is generated.
This also helps to avoid replay attacks.

The SHA256 HMAC is calculated over the first four fields, using the 'secret' parameter
as key. It is converted to a human-readable hex number and truncated to save some bandwidth.
This is the primary means of detecting corrupted or malicious packets.

VMonitor does not check the source address:port of incoming packets. If you
have static IP addresses at either side, you can add an additional layer of
security using iptables firewall.

In server mode, VMonitor learns the actual addresses:ports of the client by
looking into the source address of incoming packets. This is to support the
use cases in which the client is behind a NAT and/or has dynamic IP. This is
not a security problem since only valid packets (with correct HMAC, etc.) are
considered.

## How to run vmonitor as a service

One option is to call it from `/etc/rc.local` with the `daemon` parameter. The
app puts itself in background and redirects logging to the file configured in
`config.txt`. This is how we used this program 20 years ago.

A better, modern option is to use `systemctl`. Create the file `/etc/systemd/system/vmonitor.service`
with contents similar to the example below:

```
[Unit]
Wants=network.target

[Service]
ExecStart=/usr/local/bin/vmonitor /etc/vmonitor/config.txt client
User=root
Group=root
Restart=always
RestartSec=60

[Install]
WantedBy=multi-user.target
```

The example above assumes you copied the binary to `/usr/local/bin` and the config file to 
`/etc/vmonitor/config.txt`. In the config file, make sure to use absolute paths for the scripts.
Also, make sure you replace `client` by `server` at the server side.

Then, enable and start the service:

```
# systemctl enable vmonitor
# systemctl start vmonitor
```

Advantages of using systemctl: automatic monitoring/restarting of the service, and logging is taken
care of without having to mess with `syslogd` configuration. To check the log, look at `/var/log/syslog`
or use a command similar to

```
journalctl -u vmonitor.service -f
```
