== How to test vmonitor locally ==

You can use the file config.txt.test as a configuration file that uses loopback network
(127.0.0.1) without needing a connection to the Internet.

You need a client and a server running to achieve two-way communication. If you 
are developing the client, start a server to test your client against it, and
vice-versa.

To run a server, do

./vmonitor configfile server

or

./gomonitor configfile server

if you have the Go version built locally, or

./exmonitor configfile server

if you have the Elixir version built locally (see below).

On the other hand, if you are testing the server side, start a client by running 

./vmonitor configfile client

or

./gomonitor configfile client

or

./exmonitor configfile client

if you have the Go or Elixir version built locally.

The Elixir version (`exmonitor`) is built with `mix escript.build`, which produces the
`exmonitor` executable at the repo root. It speaks the same wire protocol as `vmonitor`
and `gomonitor`, so any combination of the three can talk to each other.

The configuration file "configfile" is the same for the client and for the server.
