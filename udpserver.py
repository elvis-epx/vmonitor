#!/usr/bin/env python3

import socket, time, datetime
from abc import ABC, abstractmethod
from myeventloop import Timeout, Handler, EventLoop, Log, LOG_INFO, LOG_DEBUG

class UDPServerHandler(Handler):
    def __init__(self, addr, label=None):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.bind(addr)
        label = label or ("%s:%d" % addr)
        super().__init__(label, sock, socket.error)
        self.send_buf = []

    def read_callback(self):
        try:
            dgram, addr = self.fd.recvfrom(4096)
            Log.debug("Received %s" % dgram)
        except socket.error:
            Log.error("Error recvfrom")
            return
        self.recv_callback(addr, dgram)

    # Called when connection receives new data
    # You must override this
    @abstractmethod
    def recv_callback(self, addr, dgram):
        pass

    def is_writable(self):
        return not not self.send_buf

    def write_callback(self):
        self.send_callback()

    def send_callback(self):
        try:
            self.fd.sendto(self.send_buf[0]['dgram'], 0, self.send_buf[0]['addr'])
        except socket.error as err:
            self.log_debug("exception writing sk", err)
        self.send_buf = self.send_buf[1:]

    # Use this method to add datagrams to send queue
    def sendto(self, addr, dgram):
        self.send_buf.append({'addr': addr, 'dgram': dgram})


class UDPServerEventLoop(EventLoop):
    def __init__(self):
        super().__init__()
