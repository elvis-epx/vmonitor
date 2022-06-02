#!/usr/bin/env python3

import time, select, datetime, os
from abc import ABC, abstractmethod

LOG_ERROR = 0
LOG_WARN = 1
LOG_INFO = 2
LOG_DEBUG = 3

class Log:
    log_level = LOG_DEBUG
    logfile = None
    is_daemon = False

    mail_level = LOG_INFO
    mail_from = "None"
    mail_to = "None"

    @staticmethod
    def set_level(new_level):
        Log.log_level = new_level

    @staticmethod
    def set_mail(mail_level, mail_from, mail_to):
        Log.mail_level = mail_level
        Log.mail_from = mail_from
        Log.mail_to = mail_to

    @staticmethod
    def set_file(f):
        if f != "None":
            Log.logfile = open(f, "a")

    @staticmethod
    def daemonize():
        Log.is_daemon = True

    @staticmethod
    def log(level, *msg):
        now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        msgw = now
        for item in msg:
            msgw += " "
            msgw += str(item)

        if level <= Log.log_level:
            if not Log.is_daemon:
                print(msgw, flush=True)

            if Log.logfile:
                Log.logfile.write(msgw)
                Log.logfile.write("\n")
                Log.logfile.flush()

        if level <= Log.mail_level and Log.mail_from != 'None' and Log.mail_to != 'None':
            Log.mail(msgw)

    def mail(msg):
        # credit: http://www.thinkspot.net/sheila/article.php?story=20040822174141155
        mailbody = "From: %s\r\nTo: %s\r\nSubject: vmonitor\r\n\r\n%s\r\n" % \
                        (Log.mail_from, Log.mail_to, msg);
        MAIL = "/usr/sbin/sendmail"
        p = os.popen("%s -t" % MAIL, 'w')
        p.write(mailbody)
        exitcode = p.close()

    @staticmethod
    def error(*msg):
        Log.log(LOG_ERROR, *msg)

    @staticmethod
    def warn(*msg):
        Log.log(LOG_WARN, *msg)

    @staticmethod
    def info(*msg):
        Log.log(LOG_INFO, *msg)

    @staticmethod
    def debug(*msg):
        Log.log(LOG_DEBUG, *msg)


# background() credits: http://www.noah.org/python/daemonize.py

def background():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)   # Exit first parent.
    except OSError as e:
        sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Decouple from parent environment.
    os.chdir("/")
    os.umask(0)
    os.setsid()

    # Do second fork.
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
        Log.daemonize()
    except OSError as e:
        sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)


class Timeout:
    pending = {}

    @staticmethod
    def next_relative():
        absolute_to, label = Timeout.next_absolute()
        return max(0, absolute_to - time.time()), label
 
    @staticmethod
    def next_absolute():
        to = time.time() + 999999999
        label = None
        for candidate in Timeout.pending.values():
            if candidate.absolute_to < to:
                to = candidate.absolute_to
                label = candidate.label
        return to, label

    @staticmethod
    def handle():
        for candidate in Timeout.pending.values():
            if time.time() > candidate.absolute_to:
                del Timeout.pending[id(candidate)]
                candidate._expired = True
                Log.debug("= timeout %s" % candidate.label)
                candidate.callback(candidate)
                return True
        return False

    @staticmethod
    def _cancel(timeout_object):
        if id(timeout_object) in Timeout.pending:
            del Timeout.pending[id(timeout_object)]

    @staticmethod
    def cancel_by_owner(owner):
        for candidate in list(Timeout.pending.values()):
            if owner is candidate.owner:
                del Timeout.pending[id(candidate)]

    def __init__(self, owner, label, relative_to, callback):
        self.owner = owner
        self.label = label
        self.relative_to = relative_to
        self.callback = callback
        self._restart()
        Log.debug("+ timeout %s %f" % (self.label, self.relative_to))

    def remaining(self):
        return max(0, self.absolute_to - time.time())

    def _restart(self):
        self.absolute_to = time.time() + self.relative_to
        self._expired = False
        self._cancelled = False
        Timeout.pending[id(self)] = self

    # Restart with the same timeout
    def restart(self):
        self._restart()
        Log.debug("> timeout %s %f" % (self.label, self.relative_to))

    # Restart with a different timeout
    def reset(self, relative_to):
        self.relative_to = relative_to
        self.restart()

    def cancel(self):
        self._cancelled = True
        remaining_time = self.absolute_to - time.time()
        Log.debug("- timeout %s (remaining %f)" % (self.label, remaining_time))
        Timeout._cancel(self)

    def cancelled(self):
        return self._cancelled

    def expired(self):
        return self._expired


class Handler(ABC):
    items = {}

    @staticmethod
    def readable_fds():
        fds = []
        for handler in Handler.items.values():
            if handler.is_readable():
                fds.append(handler.fd)
        return fds 

    # You may override this if you don't want to handle reads
    # but typically all sockets are selected for read
    def is_readable(self):
        return True

    # You must override and implement this
    @abstractmethod
    def read_callback(self):
        pass

    @staticmethod
    def writable_fds():
        fds = []
        for handler in Handler.items.values():
            if handler.is_writable():
                fds.append(handler.fd)
        return fds 

    # Override if you need to do buffered write
    def is_writable(self):
        return False

    # Override if you need to do buffered write
    def write_callback(self):
        pass

    @staticmethod
    def exception_fds():
        fds = []
        for handler in Handler.items.values():
            if handler.is_exceptionable():
                fds.append(handler.fd)
        return fds 

    # Override if you don't want to handle exceptions
    def is_exceptionable(self):
        return True

    # Override if you need more elaborate handling of exceptions/errors
    def exception_callback(self):
        self.destroy()

    @staticmethod
    def find_by_fd(fd):
        for handler in Handler.items.values():
            if fd is handler.fd:
                return handler
        return None

    def __init__(self, label, fd, fd_exceptions):
        self.label = label
        self.fd = fd
        self.fd_exceptions = fd_exceptions
        Handler.items[id(self)] = self

    # extend if you need to do more upon destruction
    def destroy(self):
        self.log_debug("destroyed")
        del Handler.items[id(self)]
        Timeout.cancel_by_owner(self)
        try:
            self.fd.close()
        except self.fd_exceptions:
            pass

    def log_error(self, *msg):
        Log.error(self.label, *msg)

    def log_warn(self, *msg):
        Log.warn(self.label, *msg)

    def log_info(self, *msg):
        Log.info(self.label, *msg)

    def log_debug(self, *msg):
        Log.debug(self.label, *msg)


class EventLoop:
    def __init__(self):
        pass

    def loop(self):
        while self.cycle():
            pass
        Log.warn("Exiting")

    # override to change behavior
    def started_cycle(self):
        pass

    # override to change behavior
    def before_select(self, crd, cwr, cex, next_to, to_label):
        if to_label:
            Log.debug("Next timeout %f %s" % (next_to, to_label))

    def cycle(self):
        self.started_cycle()

        crd = Handler.readable_fds()
        cwr = Handler.writable_fds()
        cex = Handler.exception_fds()
        next_to, to_label = Timeout.next_relative()

        if not crd and not cwr and not cex and not to_label:
            Log.warn("No remaining tasks")
            return False

        self.before_select(crd, cwr, cex, next_to, to_label)

        rd, wr, ex = select.select(crd, cwr, cex, next_to)

        if rd:
            handler = Handler.find_by_fd(rd[0])
            handler.read_callback()
        elif wr:
            handler = Handler.find_by_fd(wr[0])
            handler.write_callback()
        elif ex:
            handler = Handler.find_by_fd(ex[0])
            handler.exception_callback()
        else:
            Timeout.handle()

        return True
