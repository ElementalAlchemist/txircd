# -*- coding: utf-8 -*-
from twisted.internet import reactor
from twisted.internet.defer import DeferredList
from twisted.internet.protocol import Factory
from twisted.internet.task import LoopingCall
from twisted.internet.interfaces import ISSLTransport
from twisted.python import log
from twisted.python.logfile import DailyLogFile
from twisted.words.protocols import irc
from txircd.utils import CaseInsensitiveDictionary, DefaultCaseInsensitiveDictionary, VALID_USERNAME, now, irc_lower
from txircd.mode import ChannelModes
from txircd.server import IRCServer
from txircd.service import IRCService
from txircd.user import IRCUser
import uuid, socket, collections, yaml, os

irc.RPL_CREATIONTIME = "329"
irc.RPL_WHOISACCOUNT = "330"
irc.RPL_TOPICWHOTIME = "333"
irc.RPL_WHOISSECURE  = "671"


default_options = {
    "verbose": False,
    "irc_port": 6667,
    "ssl_port": 6697,
    "name": "txircd",
    "hostname": socket.getfqdn(),
    "motd": "Welcome to txIRCD",
    "motd_line_length": 80,
    "client_timeout": 180,
    "oper_hosts": ["127.0.0.1","localhost"],
    "opers": {"admin":"password"},
    "vhosts": {"127.0.0.1":"localhost"},
    "log_dir": "logs",
    "max_data": 5, # Bytes per 5 seconds
    "maxConnectionsPerPeer": 3,
    "maxConnectionExempt": {"127.0.0.1":0},
    "ping_interval": 30,
    "timeout_delay": 90,
}

Channel = collections.namedtuple("Channel",["name","created","topic","users","mode","log"])

class IRCProtocol(irc.IRC):
    UNREGISTERED_COMMANDS = ["PASS", "USER", "SERVICE", "SERVER", "NICK", "PING", "QUIT"]

    def __init__(self, *args, **kwargs):
        self.type = None
        self.password = None
        self.nick = None
        self.user = None
        self.secure = False
        self.data = 0
        self.data_checker = LoopingCall(self.checkData)
        self.pinger = LoopingCall(self.ping)
        self.last_message = None
    
    def connectionMade(self):
        self.secure = ISSLTransport(self.transport, None) is not None
        self.data_checker.start(5)
        self.last_message = now()
        self.pinger.start(self.factory.ping_interval)

    def dataReceived(self, data):
        self.data += len(data)
        self.last_message = now()
        if self.pinger.running:
            self.pinger.reset()
        irc.IRC.dataReceived(self, data)
    
    def checkData(self):
        if self.type:
            self.type.checkData(self.data)
        self.data = 0
    
    def ping(self):
        if (now() - self.last_message).total_seconds() > self.factory.timeout_delay:
            self.transport.loseConnection()
        else:
            self.sendMessage("PING",":{}".format(self.factory.hostname), prefix=self.factory.hostname)
    
    def handleCommand(self, command, prefix, params):
        log.msg("handleCommand: {!r} {!r} {!r}".format(command, prefix, params))
        if not self.type and command not in self.UNREGISTERED_COMMANDS:
            return self.sendMessage(irc.ERR_NOTREGISTERED, command, ":You have not registered", prefix=self.hostname)
        elif not self.type:
            return irc.IRC.handleCommand(self, command, prefix, params)
        else:
            return self.type.handleCommand(command, prefix, params)
        

    def sendLine(self, line):
        log.msg("sendLine: {!r}".format(line))
        return irc.IRC.sendLine(self, line)

    def irc_PASS(self, prefix, params):
        if not params:
            return self.sendMessage(irc.ERR_NEEDMOREPARAMS, "PASS", ":Not enough parameters", prefix=self.hostname)
        self.password = params

    def irc_NICK(self, prefix, params):
        if not params:
            self.sendMessage(irc.ERR_NONICKNAMEGIVEN, ":No nickname given", prefix=self.hostname)
        elif not VALID_USERNAME.match(params[0]):
            self.sendMessage(irc.ERR_ERRONEUSNICKNAME, params[0], ":Erroneous nickname", prefix=self.hostname)
        elif params[0] in self.factory.users:
            self.sendMessage(irc.ERR_NICKNAMEINUSE, self.factory.users[params[0]].nickname, ":Nickname is already in use", prefix=self.hostname)
        else:
            self.nick = params[0]
            if self.user:
                try:
                    self.type = IRCUser(self, self.user, self.password, self.nick)
                except ValueError:
                    self.type = None
                    self.transport.loseConnection()

    def irc_USER(self, prefix, params):
        if len(params) < 4:
            return self.sendMessage(irc.ERR_NEEDMOREPARAMS, "USER", ":Not enough parameters", prefix=self.hostname)
        self.user = params
        if self.nick:
            try:
                self.type = self.factory.types["user"](self, self.user, self.password, self.nick)
            except ValueError:
                self.type = None
                self.transport.loseConnection()

    def irc_SERVICE(self, prefix, params):
        try:
            self.type = self.factory.types["service"](self, params, self.password)
        except ValueError:
            self.type = None
            self.transport.loseConnection()

    def irc_SERVER(self, prefix, params):
        try:
            self.type = self.factory.types["server"](self, params, self.password)
        except ValueError:
            self.type = None
            self.transport.loseConnection()

    def irc_PING(self, prefix, params):
        if params:
            self.sendMessage("PONG", self.factory.hostname, ":{}".format(params[0]), prefix=self.factory.hostname)
        else: # TODO: There's no nickname here, what do?
            self.sendMessage(irc.ERR_NOORIGIN, "CHANGE_THIS", ":No origin specified", prefix=self.factory.hostname)

    def irc_QUIT(self, prefix, params):
        self.transport.loseConnection()
        
    def connectionLost(self, reason):
        if self.type:
            self.type.connectionLost(reason)
        if self.data_checker.running:
            self.data_checker.stop()
        if self.pinger.running:
            self.pinger.stop()

class IRCD(Factory):
    protocol = IRCProtocol
    channel_prefixes = "#"
    types = {
        "user": IRCUser,
        "server": IRCServer,
        "service": IRCService,
    }
    prefix_order = "qaohv" # Hardcoded into modes :(
    prefix_symbols = {
        "q": "~",
        "a": "&",
        "o": "@",
        "h": "%",
        "v": "+"
    }

    def __init__(self, config, options = None):
        self.config = config
        self.config_vars = ["name","hostname","motd","motd_line_length","client_timeout",
            "oper_hosts","opers","vhosts","log_dir","max_data","maxConnectionsPerPeer",
            "maxConnectionExempt","ping_interval","timeout_delay"]
        if not options:
            options = {}
        self.load_options(options)
        self.version = "0.1"
        self.created = now()
        self.token = uuid.uuid1()
        self.servers = CaseInsensitiveDictionary()
        self.users = CaseInsensitiveDictionary()
        self.channels = DefaultCaseInsensitiveDictionary(self.ChannelFactory)
        self.peerConnections = {}
        reactor.addSystemEventTrigger('before', 'shutdown', self.cleanup)
    
    def rehash(self):
        try:
            with open(self.config) as f:
                self.load_options(yaml.safe_load(f))
        except:
            return False
        return True
    
    def load_options(self, options):
        for var in self.config_vars:
            setattr(self, var, options[var] if var in options else default_options[var])
    
    def save_options(self):
        options = {}
        try:
            with open(self.config) as f:
                options = yaml.safe_load(f)
        except:
            return False
        for var in self.config_vars:
            options[var] = getattr(self, var, None)
        try:
            with open(self.config,"w") as f:
                yaml.dump(options, f, default_flow_style=False)
        except:
            return False
        return True
    
    def cleanup(self):
        # Track the disconnections so we know they get done
        deferreds = []
        # Cleanly disconnect all clients
        log.msg("Disconnecting clients...")
        for u in self.users.values():
            u.irc_QUIT(None,["Server shutting down"])
            deferreds.append(u.disconnected)
        # Without any clients, all channels should be gone
        # But make sure the logs are closed, just in case
        log.msg("Closing logs...")
        for c in self.channels.itervalues():
            c.log.close()
        # Finally, save the config. Just in case.
        log.msg("Saving options...")
        self.save_options()
        # Return deferreds
        return DeferredList(deferreds)
    
    def buildProtocol(self, addr):
        ip = addr.host
        conn = self.peerConnections.get(ip,0)
        max = self.maxConnectionExempt[ip] if ip in self.maxConnectionExempt else self.maxConnectionsPerPeer
        if max and conn >= max:
            return None
        self.peerConnections[ip] = conn + 1
        return Factory.buildProtocol(self, addr)
    
    def ChannelFactory(self, name):
        logfile = "{}/{}".format(self.log_dir,irc_lower(name))
        if not os.path.exists(logfile):
            os.makedirs(logfile)
        c = Channel(name,now(),{"message":None,"author":"","created":now()},CaseInsensitiveDictionary(),ChannelModes(self,None),DailyLogFile("log",logfile))
        c.mode.parent = c
        c.mode.combine("nt",[],name)
        return c
