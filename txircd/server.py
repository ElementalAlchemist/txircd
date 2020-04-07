from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.task import LoopingCall
from txircd.ircbase import IRCBase
from txircd.utils import now
from typing import Any, Dict, List, Optional

class IRCServer(IRCBase):
	def __init__(self, ircd, ip, received):
		self.ircd = ircd
		self.serverID = None
		self.name = None
		self.description = None
		self.ip = ip
		self.nextClosest = self.ircd.serverID
		self.cache = {}
		self.bursted = None
		self.disconnectedDeferred = Deferred()
		self.receivedConnection = received
		self._pinger = LoopingCall(self._ping)
		self._registrationTimeoutTimer = reactor.callLater(self.ircd.config.get("server_registration_timeout", 10), self._timeoutRegistration)
		self._burstQueueCommands = []
		self._burstQueueCommandPriorities = {}
		self._burstQueueHandlers = {}
		self._disconnected = False
	
	def handleCommand(self, command: str, params: List[str], prefix: str, tags: Dict[str, Optional[str]]) -> None:
		if self._disconnected:
			return # Don't process leftover commands for disconnected servers
		if command not in self.ircd.serverCommands:
			self.disconnect("Unknown command {}".format(command)) # If we receive a command we don't recognize, abort immediately to avoid a desync
			return
		handlers = self.ircd.serverCommands[command]
		data = None
		affectedUsers = []
		affectedChannels = []
		for handler in handlers:
			if self.bursted is False and handler[0].burstQueuePriority is not None:
				if command not in self._burstQueueCommands:
					handlerPriority = handler[0].burstQueuePriority
					self._burstQueueCommandPriorities[command] = handlerPriority
					for cmdIndex, queueCommand in enumerate(self._burstQueueCommands):
						queueCommandPriority = self._burstQueueCommandPriorities[queueCommand]
						if queueCommandPriority < handlerPriority:
							self._burstQueueCommands.insert(cmdIndex, command)
							break
					else:
						self._burstQueueCommands.append(command)
					self._burstQueueHandlers[command] = []
				self._burstQueueHandlers[command].append((params, prefix, tags))
				return
			registrationStatus = self.bursted
			if registrationStatus is None:
				registrationStatus = False
			if handler[0].forRegistered is not None and handler[0].forRegistered != registrationStatus:
				continue
			data = handler[0].parseParams(self, params, prefix, tags)
			if data is not None:
				affectedUsers = handler[0].affectedUsers(self, data)
				affectedChannels = handler[0].affectedChannels(self, data)
				break
		if data is None:
			self.ircd.log.error("Received command {command} from server {server.serverID} that we couldn't parse! (prefix: {prefix}; params: {params!r}; tags: {tags!r}", command=command, params=params, prefix=prefix, tags=tags, server=self)
			self.disconnect("Failed to parse command {} from {} with prefix '{}' and parameters {!r}".format(command, self.serverID, prefix, params)) # If we receive a command we can't parse, also abort immediately
			return
		for handler in handlers:
			if handler[0].execute(self, data):
				break
		else:
			self.ircd.log.error("Received command {command} from server {server.serverID} that we couldn't handle! (prefix: {prefix}; params: {params!r}; tags: {tags!r}", command=command, params=params, prefix=prefix, tags=tags, server=self)
			self.disconnect("Couldn't process command {} from {} with prefix '{}' and parameters {!r}".format(command, self.serverID, prefix, params)) # Also abort connection if we can't process a command
			return
		self.ircd.runComboActionStandard((("servercommandextra-{}".format(command), (self, data)), ("servercommandextra", (self, command, data))), users=affectedUsers, channels=affectedChannels)
	
	def endBurst(self) -> None:
		"""
		Called at the end of bursting.
		"""
		if self.bursted:
			return
		self.bursted = True
		for command in self._burstQueueCommands:
			self.ircd.runActionStandard("startburstcommand", self, command)
			self.ircd.log.debug("Processing command {command} from server {server.serverID} in burst queue", command=command, server=self)
			for params, prefix, tags in self._burstQueueHandlers[command]:
				self.handleCommand(command, params, prefix, tags)
				if self.bursted is None:
					# Something failed to process, so we disconnected
					return
			self.ircd.runActionStandard("endburstcommand", self, command)
		self._burstQueueCommands = None
		self._burstQueueCommandPriorities = None
		self._burstQueueHandlers = None
	
	def connectionLost(self, reason: str) -> None:
		if self.serverID in self.ircd.servers:
			self.disconnect("Connection reset")
		self.disconnectedDeferred.callback(None)
	
	def disconnect(self, reason: str, netsplitFromServerName: str = None, netsplitToServerName: str = None) -> None:
		"""
		Disconnects the server.
		"""
		if self.nextClosest == self.ircd.serverID:
			self.ircd.log.warn("Disconnecting server {server.serverID} ({server.name}): {reason}", server=self, reason=reason)
		else:
			self.ircd.log.warn("Removing server {server.serverID} ({server.name}): {reason}", server=self, reason=reason)
		self.ircd.runActionStandard("serverquit", self, reason)
		self.bursted = None
		self._disconnected = True
		self._endConnection()
		if self.serverID in self.ircd.servers:
			if netsplitFromServerName is None or netsplitToServerName is None:
				netsplitFromServerName = self.ircd.servers[self.nextClosest].name if self.nextClosest in self.ircd.servers else self.ircd.name
				netsplitToServerName = self.name
			netsplitQuitMsg = "{} {}".format(netsplitFromServerName, netsplitToServerName)
			allUsers = list(self.ircd.users.values())
			notifyUserBatches = set()
			notifyUsersQuitting = {}
			
			localServerNextNode = self
			while localServerNextNode.nextClosest != self.ircd.serverID:
				localServerNextNode = self.ircd.servers[localServerNextNode.nextClosest]
			
			for user in allUsers:
				if user.uuid[:3] == self.serverID:
					notifyUsersForUser = user.disconnectDeferNotify(netsplitQuitMsg, localServerNextNode)
					notifyUserBatches.update(notifyUsersForUser)
					notifyUsersQuitting[user] = notifyUsersForUser
			for user in notifyUserBatches:
				user.createMessageBatch("Netsplit", "netsplit", (netsplitFromServerName, netsplitToServerName))
			for user, notifyUsers in notifyUsersQuitting.items():
				self.ircd.runActionProcessing("quitmessage", notifyUsers, user, netsplitQuitMsg, "Netsplit", users=notifyUsers)
			for user in notifyUserBatches:
				user.sendBatch("Netsplit")
			allServers = list(self.ircd.servers.values())
			for server in allServers:
				if server.nextClosest == self.serverID:
					server.disconnect(reason, netsplitFromServerName, netsplitToServerName)
			del self.ircd.servers[self.serverID]
			del self.ircd.serverNames[self.name]
			self.ircd.recentlyQuitServers[self.serverID] = now()
		if self._pinger.running:
			self._pinger.stop()
		if self._registrationTimeoutTimer.active():
			self._registrationTimeoutTimer.cancel()
	
	def _endConnection(self) -> None:
		self.transport.loseConnection()
	
	def _timeoutRegistration(self) -> None:
		if self.serverID and self.name:
			self._pinger.start(self.ircd.config.get("server_ping_frequency", 60))
			return
		self.ircd.log.info("Disconnecting unregistered server")
		self.disconnect("Registration timeout")
	
	def _ping(self) -> None:
		self.ircd.runActionStandard("pingserver", self)
	
	def register(self) -> None:
		"""
		Marks the server as registered. Should be called once after capability
		negotiation.
		"""
		if not self.serverID:
			return
		if not self.name:
			return
		self.ircd.servers[self.serverID] = self
		self.ircd.serverNames[self.name] = self
		self.ircd.runActionStandard("serverconnect", self)
		self.ircd.log.info("Registered server {server.serverID} ({server.name})", server=self)
		if self.nextClosest != self.ircd.serverID:
			self.bursted = True # Indicate that this server is fully connected and synced NOW since it's a remote server and we've either already gotten or are about to get all the interesting tidbits

class RemoteServer(IRCServer):
	def __init__(self, ircd, ip):
		IRCServer.__init__(self, ircd, ip, True)
		self._registrationTimeoutTimer.cancel()
	
	def sendMessage(self, command: str, *params: str, **kw: Any) -> None:
		"""
		Sends a message to the locally-connected server that will route to the
		remote server.
		Messages sent this way should have some information in the contents so
		that they can be propagated in the correct direction.
		"""
		target = self
		while target.nextClosest != self.ircd.serverID:
			target = self.ircd.servers[target.nextClosest]
		target.sendMessage(command, *params, **kw)
	
	def _endConnection(self) -> None:
		pass