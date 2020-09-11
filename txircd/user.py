from twisted.internet import reactor
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import ISSLTransport
from twisted.internet.task import LoopingCall
from twisted.names import client as dnsClient
from twisted.words.protocols import irc
from txircd import version
from txircd.ircbase import IRCBase
from txircd.utils import CaseInsensitiveDictionary, ipAddressToShow, isValidHost, isValidMetadataKey, lenBytes, ModeType, now, splitMessage
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

irc.ERR_ALREADYREGISTERED = "462"

class IRCUser(IRCBase):
	def __init__(self, ircd: "IRCd", ip: Union["IPv4Address", "IPv6Address"], uuid: str = None, host: str = None):
		self.ircd = ircd
		self.uuid = ircd.createUUID() if uuid is None else uuid
		
		registrationTimeout = self.ircd.config.get("user_registration_timeout", 10)
		
		self.nick = None
		self.ident = None
		if host is None:
			self.realHost = ipAddressToShow(ip)
		else:
			self.realHost = host
		self.ip = ip
		self._hostStack = []
		self._hostsByType = {}
		self.gecos = None
		self._metadata = CaseInsensitiveDictionary()
		self.cache = {}
		self.channels = []
		self.modes = {}
		self.connectedSince = now()
		self.nickSince = now()
		self.idleSince = now()
		self._registerHolds = set(("connection", "dns", "NICK", "USER"))
		self.disconnectedDeferred = Deferred()
		self._messageBatches = {}
		self._errorBatchName = None
		self._errorBatch = []
		self.ircd.users[self.uuid] = self
		self.localOnly = False
		self.secureConnection = False
		self._pinger = LoopingCall(self._ping)
		self._registrationTimeoutTimer = reactor.callLater(registrationTimeout, self._timeoutRegistration)
		self._startDNSResolving(registrationTimeout)
	
	def _startDNSResolving(self, timeout: int) -> None:
		resolveDeferred = dnsClient.lookupPointer(self.ip.reverse_pointer, ((timeout/2),))
		resolveDeferred.addCallbacks(callback=self._verifyDNSResolution, callbackArgs=(timeout,), errback=self._cancelDNSResolution)
	
	def _verifyDNSResolution(self, result: Tuple[List["RRHeader"], List["RRHeader"], List["RRHeader"]], timeout: int) -> None:
		resolveResults = result[0]
		if not resolveResults:
			self._cancelDNSResolution()
			return
		name = resolveResults[0].payload.name.name.decode("utf-8", "replace")
		if lenBytes(name) > self.ircd.config.get("hostname_length", 64):
			self._cancelDNSResolution()
			return
		if not isValidHost(name):
			self._cancelDNSResolution()
			return
		if self.ip.version == 4:
			resolveDeferred = dnsClient.lookupAddress(name, ((timeout/2),))
		else:
			resolveDeferred = dnsClient.lookupIPV6Address(name, ((timeout/2),))
		resolveDeferred.addCallbacks(callback=self._completeDNSResolution, errback=self._cancelDNSResolution, callbackArgs=(name,))
	
	def _completeDNSResolution(self, result: Tuple[List["RRHeader"], List["RRHeader"], List["RRHeader"]], name: str) -> None:
		addressResults = result[0]
		for addressData in addressResults:
			if hasattr(addressData.payload, "address") and addressData.payload.address == self.ip.packed:
				self.realHost = name
				break
		self.register("dns")
	
	def _cancelDNSResolution(self, error: "Failure" = None) -> None:
		self.register("dns")
	
	def connectionMade(self) -> None:
		# We need to callLater the connect action call because the connection isn't fully set up yet,
		# nor is it fully set up even with a delay of zero, which causes the message buffer not to be sent
		# when the connection is closed.
		# The "connection" register hold is used basically solely for the purposes of this to prevent potential
		# race conditions with registration.
		if ISSLTransport.providedBy(self.transport):
			self.secureConnection = True
		self._callConnectAction()
	
	def _callConnectAction(self) -> None:
		self.ircd.log.debug("User {user.uuid} connected from {ip}", user=self, ip=ipAddressToShow(self.ip))
		if self.ircd.runActionUntilFalse("userconnect", self, users=[self]):
			self.transport.loseConnection()
			return
		self.register("connection")
	
	def dataReceived(self, data: bytes) -> None:
		self.ircd.runActionStandard("userrecvdata", self, data, users=[self])
		try:
			IRCBase.dataReceived(self, data)
		except Exception:
			self.ircd.log.failure("An error occurred while processing incoming data.")
			if self.uuid in self.ircd.users:
				self.disconnect("Error occurred")
	
	def sendLine(self, line: str) -> None:
		self.ircd.runActionStandard("usersenddata", self, line, users=[self])
		IRCBase.sendLine(self, line)
	
	def sendMessage(self, command: str, *args: str, **kw: Any) -> None:
		"""
		Sends the given message to this user.
		Accepts the following keyword arguments:
		- prefix: The message prefix or None to suppress the default prefix
		    If not given, defaults to the server name.
		- to: The destination of the message or None if the message has no
		    destination. The implicit destination is this user if this
		    argument isn't specified.
		- tags: Dict of message tags to send.
		- alwaysPrefixLastParam: For compatibility with some broken clients,
		    you might want some messages to always have the last parameter
		    prefixed with a colon. To do that, pass this as True.
		"""
		if "prefix" not in kw:
			kw["prefix"] = self.ircd.name
		if kw["prefix"] is None:
			del kw["prefix"]
		to = self.nick if self.nick else "*"
		if "to" in kw:
			to = kw["to"]
			del kw["to"]
		if to:
			args = [to] + list(args)
		tags = kw["tags"] if "tags" in kw else {}
		self.ircd.runActionStandard("outgoingmessagetags", self, command, to, tags)
		IRCBase.sendMessage(self, command, *args, **kw)
		self.ircd.runActionStandard("sentmessage", self, command, args, kw)
	
	def handleCommand(self, command: str, params: List[str], prefix: str, tags: Dict[str, Optional[str]]) -> None:
		if self.uuid not in self.ircd.users:
			return # we have been disconnected - ignore all further commands
		if command in self.ircd.userCommands:
			handlers = self.ircd.userCommands[command]
			if not handlers:
				return
			data = None
			spewRegWarning = True
			affectedUsers = []
			affectedChannels = []
			for handler in handlers:
				if handler[0].forRegistered is not None:
					if (handler[0].forRegistered is True and not self.isRegistered()) or (handler[0].forRegistered is False and self.isRegistered()):
						continue
				spewRegWarning = False
				data = handler[0].parseParams(self, params, prefix, tags)
				if data is not None:
					affectedUsers = handler[0].affectedUsers(self, data)
					affectedChannels = handler[0].affectedChannels(self, data)
					if self not in affectedUsers:
						affectedUsers.append(self)
					break
			if data is None:
				if spewRegWarning:
					if self.isRegistered():
						self.sendMessage(irc.ERR_ALREADYREGISTERED, "You may not reregister")
					else:
						self.sendMessage(irc.ERR_NOTREGISTERED, command, "You have not registered")
				elif self._hasBatchedErrors():
					self._dispatchErrorBatch()
				return
			self._clearErrorBatch()
			if self.ircd.runComboActionUntilValue((("commandpermission-{}".format(command), (self, data)), ("commandpermission", (self, command, data))), users=affectedUsers, channels=affectedChannels) is False:
				return
			self.ircd.runComboActionStandard((("commandmodify-{}".format(command), (self, data)), ("commandmodify", (self, command, data))), users=affectedUsers, channels=affectedChannels) # This allows us to do processing without the "stop on empty" feature of runActionProcessing
			for handler in handlers:
				if handler[0].execute(self, data):
					if handler[0].resetsIdleTime:
						self.idleSince = now()
					break # If the command executor returns True, it was handled
			else:
				return # Don't process commandextra if it wasn't handled
			self.ircd.runComboActionStandard((("commandextra-{}".format(command), (self, data)), ("commandextra", (self, command, data))), users=affectedUsers, channels=affectedChannels)
		else:
			if not self.ircd.runActionFlagTrue("commandunknown", self, command, params, {}):
				self.sendMessage(irc.ERR_UNKNOWNCOMMAND, command, "Unknown command")
	
	def createMessageBatch(self, batchName: str, batchType: str, batchParameters: List[Any] = None) -> None:
		"""
		Start a new message batch with the given batch name, type, and list of parameters.
		If a batch with the given name already exists, that batch will be overwritten.
		"""
		self._messageBatches[batchName] = { "type": batchType, "parameters": batchParameters, "messages": [] }
	
	def sendMessageInBatch(self, batchName: str, command: str, *args: str, **kw: Any) -> None:
		"""
		Adds a message to the batch with the given name.
		"""
		if batchName not in self._messageBatches:
			return
		self._messageBatches[batchName]["messages"].append((command, args, kw))
	
	def sendBatch(self, batchName: str) -> None:
		"""
		Sends the messages in the given batch to the user.
		"""
		if batchName not in self._messageBatches:
			return
		batchType = self._messageBatches[batchName]["type"]
		batchParameters = self._messageBatches[batchName]["parameters"]
		self.ircd.runActionStandard("startbatchsend", self, batchName, batchType, batchParameters)
		for messageData in self._messageBatches[batchName]["messages"]:
			self.sendMessage(messageData[0], *messageData[1], **messageData[2])
		self.ircd.runActionStandard("endbatchsend", self, batchName, batchType, batchParameters)
		del self._messageBatches[batchName]
	
	def startErrorBatch(self, batchName: str) -> None:
		"""
		Used to start an error batch when sending multiple error messages to a
		user from a command's parseParams or from the commandpermission action.
		"""
		if not self._errorBatchName or not self._errorBatch: # Only the first batch should apply
			self._errorBatchName = batchName
		
	def sendBatchedError(self, batchName: str, command: str, *args: str, **kw: Any) -> None:
		"""
		Adds an error to the current error batch if the specified error batch
		is the current error batch.
		"""
		if batchName and self._errorBatchName == batchName:
			self._errorBatch.append((command, args, kw))
	
	def sendSingleError(self, batchName: str, command: str, *args: str, **kw: Any) -> None:
		"""
		Creates a batch containing a single error and adds the specified error
		to it.
		"""
		if not self._errorBatchName:
			self._errorBatchName = batchName
			self._errorBatch.append((command, args, kw))
	
	def _hasBatchedErrors(self) -> bool:
		if self._errorBatch:
			return True
		return False
	
	def _clearErrorBatch(self) -> None:
		self._errorBatchName = None
		self._errorBatch = []
	
	def _dispatchErrorBatch(self) -> None:
		for error in self._errorBatch:
			self.sendMessage(error[0], *error[1], **error[2])
		self._clearErrorBatch()
	
	def filterConditionalTags(self, conditionalTags: Dict[str, Tuple[str, Callable[[Optional[str]], bool]]]) -> Dict[str, Optional[str]]:
		applyTags = {}
		for tag, data in conditionalTags.items():
			value, check = data
			if check(self):
				applyTags[tag] = value
		return applyTags
	
	def connectionLost(self, reason: str) -> None:
		if self.uuid in self.ircd.users:
			self.disconnect("Connection reset")
		self.disconnectedDeferred.callback(None)
	
	def disconnect(self, reason: str, fromServer: "IRCServer" = None) -> None:
		"""
		Disconnects the user from the server.
		"""
		self.ircd.log.debug("Disconnecting user {user.uuid} ({hostmask()}) [from {serverID}]: {reason}", user=self, hostmask=self.hostmask, serverID=fromServer.serverID if fromServer else "local server", reason=reason)
		# Sometimes, actions deferred from initial connection may cause registration to occur after disconnection if
		# disconnection happens before registration completes. If the user is unregistered on disconnection, this prevents
		# the user from completing registration.
		self.addRegisterHold("QUIT")
		if self._pinger:
			if self._pinger.running:
				self._pinger.stop()
			self._pinger = None
		if self._registrationTimeoutTimer:
			if self._registrationTimeoutTimer.active():
				self._registrationTimeoutTimer.cancel()
			self._registrationTimeoutTimer = None
		self.ircd.recentlyQuitUsers[self.uuid] = now()
		del self.ircd.users[self.uuid]
		if self.isRegistered():
			del self.ircd.userNicks[self.nick]
		userSendList = [self]
		while self.channels:
			channel = self.channels[0]
			userSendList.extend(channel.users.keys())
			self._leaveChannel(channel, "QUIT", { "reason": reason })
		userSendList = [u for u in set(userSendList) if u.uuid[:3] == self.ircd.serverID]
		userSendList.remove(self)
		self.ircd.runActionProcessing("quitmessage", userSendList, self, reason, None, users=[self] + userSendList)
		self.ircd.runActionStandard("quit", self, reason, fromServer, users=[self], allowDisconnected=True)
		self.transport.loseConnection()
	
	def _timeoutRegistration(self) -> None:
		if self.isRegistered():
			self._pinger.start(self.ircd.config.get("user_ping_frequency", 60), False)
			return
		self.disconnect("Registration timeout")
	
	def _ping(self) -> None:
		self.ircd.runActionStandard("pinguser", self)
	
	def isRegistered(self) -> bool:
		"""
		Returns True if this user session is fully registered.
		"""
		return not self._registerHolds
	
	def register(self, holdName: str) -> None:
		"""
		Removes the specified hold on a user's registration. If this is the
		last hold on a user, completes registration on the user.
		"""
		if holdName not in self._registerHolds:
			return
		self._registerHolds.remove(holdName)
		if not self._registerHolds:
			if not self.nick or self.nick in self.ircd.userNicks:
				self._registerHolds.add("NICK")
			if not self.ident or not self.gecos:
				self._registerHolds.add("USER")
			if self._registerHolds:
				return
			self._registerHolds.add("registercheck") # The user shouldn't be considered registered until we complete these final checks
			if self.ircd.runActionUntilFalse("register", self, users=[self]):
				self.transport.loseConnection()
				return
			self._registerHolds.remove("registercheck")
			self.ircd.userNicks[self.nick] = self
			self.ircd.log.debug("Registering user {user.uuid} ({userHostmask()})", user=self, userHostmask=self.hostmask)
			versionWithName = "txircd-{}".format(version)
			self.sendMessage(irc.RPL_WELCOME, "Welcome to the {} Internet Relay Chat Network {}".format(self.ircd.config["network_name"], self.hostmask()))
			self.sendMessage(irc.RPL_YOURHOST, "Your host is {}, running version {}".format(self.ircd.name, versionWithName))
			self.sendMessage(irc.RPL_CREATED, "This server was created {}".format(self.ircd.startupTime.replace(microsecond=0)))
			chanModes = "".join(["".join(modes.keys()) for modes in self.ircd.channelModes])
			chanModes += "".join(self.ircd.channelStatuses.keys())
			self.sendMessage(irc.RPL_MYINFO, self.ircd.name, versionWithName, "".join(["".join(modes.keys()) for modes in self.ircd.userModes]), chanModes)
			self.sendISupport()
			self.ircd.runActionStandard("welcome", self, users=[self])
	
	def addRegisterHold(self, holdName: str) -> None:
		"""
		Adds a register hold to this user if the user is not yet registered.
		"""
		if not self._registerHolds:
			return
		self._registerHolds.add(holdName)
	
	def sendISupport(self) -> None:
		"""
		Sends ISUPPORT to this user."""
		isupportList = self.ircd.generateISupportList()
		isupportMsgList = splitMessage(" ".join(isupportList), 350)
		for line in isupportMsgList:
			lineArgs = line.split(" ")
			lineArgs.append("are supported by this server")
			self.sendMessage(irc.RPL_ISUPPORT, *lineArgs)
	
	def hostmask(self) -> str:
		"""
		Returns the user's hostmask.
		"""
		return "{}!{}@{}".format(self.nick, self.ident, self.host())
	
	def hostmaskWithRealHost(self) -> str:
		"""
		Returns the user's hostmask using the user's real host rather than any
		vhost that may have been applied.
		"""
		return "{}!{}@{}".format(self.nick, self.ident, self.realHost)
	
	def hostmaskWithIP(self) -> str:
		"""
		Returns the user's hostmask using the user's IP address instead of the
		host.
		"""
		return "{}!{}@{}".format(self.nick, self.ident, ipAddressToShow(self.ip))
	
	def changeNick(self, newNick: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes this user's nickname. If initiated by a remote server, that
		server should be specified in the fromServer parameter.
		"""
		if newNick == self.nick:
			return
		if newNick in self.ircd.userNicks and self.ircd.userNicks[newNick] != self:
			return
		oldNick = self.nick
		if oldNick and oldNick in self.ircd.userNicks:
			del self.ircd.userNicks[oldNick]
		self.nick = newNick
		self.nickSince = now()
		if self.isRegistered():
			self.ircd.userNicks[self.nick] = self
			userSendList = [self]
			for channel in self.channels:
				userSendList.extend(channel.users.keys())
			userSendList = [u for u in set(userSendList) if u.uuid[:3] == self.ircd.serverID]
			self.ircd.runActionProcessing("changenickmessage", userSendList, self, oldNick, users=userSendList)
			self.ircd.runActionStandard("changenick", self, oldNick, fromServer, users=[self])
	
	def changeIdent(self, newIdent: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes this user's ident. If initiated by a remote server, that server
		should be specified in the fromServer parameter.
		"""
		if newIdent == self.ident:
			return
		if lenBytes(newIdent) > self.ircd.config.get("ident_length", 12):
			return
		oldIdent = self.ident
		self.ident = newIdent
		if self.isRegistered():
			self.ircd.runActionStandard("changeident", self, oldIdent, fromServer, users=[self])
	
	def host(self) -> str:
		if not self._hostStack:
			return self.realHost
		return self._hostsByType[self._hostStack[-1]]
	
	def changeHost(self, hostType: str, newHost: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes a user's host. If initiated by a remote server, that server
		should be specified in the fromServer parameter.
		"""
		if hostType == "*":
			return
		if lenBytes(newHost) > self.ircd.config.get("hostname_length", 64):
			return
		if hostType in self._hostsByType and self._hostsByType[hostType] == newHost:
			return
		oldHost = self.host()
		self._hostsByType[hostType] = newHost
		if hostType in self._hostStack:
			self._hostStack.remove(hostType)
		self._hostStack.append(hostType)
		if self.isRegistered():
			self.ircd.runComboActionStandard((("changehost", (self, hostType, oldHost, fromServer)), ("updatehost", (self, hostType, oldHost, newHost, fromServer))), users=[self])
	
	def updateHost(self, hostType: str, newHost: str, fromServer: "IRCServer" = None) -> None:
		"""
		Updates the host of a given host type for the user. If initiated by
		a remote server, that server should be specified in the fromServer
		parameter.
		"""
		if hostType not in self._hostStack:
			self.changeHost(hostType, newHost, fromServer)
			return
		if hostType == "*":
			return
		if lenBytes(newHost) > self.ircd.config.get("hostname_length", 64):
			return
		if hostType in self._hostsByType and self._hostsByType[hostType] == newHost:
			return
		oldHost = self.host()
		oldHostOfType = None
		if hostType in self._hostsByType:
			oldHostOfType = self._hostsByType[hostType]
		self._hostsByType[hostType] = newHost
		changedUserHost = (oldHost != self.host())
		changedHostOfType = (oldHostOfType != newHost)
		if self.isRegistered():
			if changedUserHost and changedHostOfType:
				self.ircd.runComboActionStandard((("changehost", (self, hostType, oldHost, fromServer)), ("updatehost", (self, hostType, oldHost, newHost, fromServer))), users=[self])
			elif changedHostOfType:
				self.ircd.runActionStandard("updatehost", self, hostType, oldHost, newHost, fromServer, users=[self])
	
	def resetHost(self, hostType: str, fromServer: "IRCServer" = None) -> None:
		"""
		Resets the user's host to the real host.
		"""
		if hostType not in self._hostsByType:
			return
		oldHost = self.host()
		if hostType in self._hostStack:
			self._hostStack.remove(hostType)
		del self._hostsByType[hostType]
		currentHost = self.host()
		if currentHost != oldHost:
			self.ircd.runComboActionStandard((("changehost", (self, hostType, oldHost, fromServer)), ("updatehost", (self, hostType, oldHost, None, fromServer))), users=[self])
		else:
			self.ircd.runActionStandard("updatehost", self, hostType, oldHost, None, fromServer, users=[self])
	
	def currentHostType(self) -> str:
		if self._hostStack:
			return self._hostStack[-1]
		return "*"
	
	def changeGecos(self, newGecos: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes a user's real name. If initiated by a remote server, that
		server should be specified in the fromServer parameter.
		"""
		if lenBytes(newGecos) > self.ircd.config.get("gecos_length", 128):
			return
		if newGecos == self.gecos:
			return
		oldGecos = self.gecos
		self.gecos = newGecos
		if self.isRegistered():
			self.ircd.runActionStandard("changegecos", self, oldGecos, fromServer, users=[self])
	
	def changeIP(self, ip: Union["IPv4Address", "IPv6Address"]) -> None:
		"""
		Changes a user's IP address.
		This must be done before registration is complete.
		"""
		if self.isRegistered():
			return
		oldIP = self.ip
		self.ip = ip
		self.ircd.runActionStandard("changeipaddress", self, oldIP, users=[self])
	
	def metadataKeyExists(self, key: str) -> bool:
		"""
		Checks whether the specified key exists in the user's metadata.
		"""
		return key in self._metadata
	
	def metadataKeyCase(self, key: str) -> Optional[str]:
		"""
		Returns the specified key in the user's metadata in its original case.
		Returns None if the given key is not in the user's metadata.
		"""
		if key not in self._metadata:
			return None
		return self._metadata[key][0]
	
	def metadataValue(self, key: str) -> Optional[str]:
		"""
		Returns the value of the given key in the user's metadata or None if
		the given key is not in the user's metadata.
		"""
		if key not in self._metadata:
			return None
		return self._metadata[key][1]
	
	def metadataKeySetTime(self, key: str) -> Optional["datetime"]:
		"""
		Returns the time a key was set in the user's metadata or None if the
		given key is not in the user's metadata.
		"""
		if key not in self._metadata:
			return None
		return self._metadata[key][2]
	
	def metadataList(self) -> List[Tuple[str, str, "datetime"]]:
		"""
		Returns the list of metadata keys/values for the user as a list of
		tuples in the format
		[ (key, value, setTime) ]
		"""
		return list(self._metadata.values())
	
	def setMetadata(self, key: str, value: Optional[str], fromServer: "IRCServer" = None) -> bool:
		"""
		Sets metadata for the user. If initiated by a remote server, that
		server should be specified in the fromServer parameter.
		If the value is None, deletes the metadata at the provided key.
		"""
		if not isValidMetadataKey(key):
			return False
		oldData = None
		if key in self._metadata:
			oldData = self._metadata[key]
		
		if value is None:
			if key in self._metadata:
				del self._metadata[key]
		else:
			self._metadata[key] = (key, value)
		oldValue = oldData[1] if oldData else None
		self.ircd.runActionStandard("usermetadataupdate", self, key, oldValue, value, fromServer, users=[self])
		return True
	
	def joinChannel(self, channel: "IRCChannel", override: bool = False, fromServer: "IRCServer" = None) -> None:
		"""
		Joins the user to a channel. Specify the override parameter only if all
		permission checks should be bypassed.
		"""
		joinChannelData = self.joinChannelNoAnnounceIncomplete(channel, override, fromServer)
		if not joinChannelData:
			return
		messageUsers = self.joinChannelNoAnnounceNotifyUsers(joinChannelData)
		self.ircd.runActionProcessing("joinmessage", messageUsers, channel, self, None, users=messageUsers, channels=[channel])
		self.joinChannelNoAnnounceFinish(joinChannelData)
	
	def joinChannelNoAnnounceIncomplete(self, channel: "IRCChannel", override: bool = False, fromServer: "IRCServer" = None) -> Dict[str, Any]:
		"""
		Joins the user to a channel, but doesn't announce or do any actions to complete
		the join. As with joinChannel, specify the override parameter only if all
		permission checks should be bypassed.
		Returns a dict of data that MUST be passed to joinChannelNoAnnounceFinish.
		For a list of users to notify, pass the dict to joinChannelNoAnnounceNotifyUsers.
		"""
		if channel in self.channels:
			return None
		if not override and not fromServer:
			if self.ircd.runActionUntilValue("joinpermission", channel, self, users=[self], channels=[channel]) is False:
				return None
		channel.users[self] = { "status": "" }
		self.channels.append(channel)
		newChannel = False
		if channel.name not in self.ircd.channels:
			newChannel = True
			self.ircd.channels[channel.name] = channel
			self.ircd.recentlyDestroyedChannels[channel.name] = False
		messageUsers = [u for u in channel.users.keys() if u.uuid[:3] == self.ircd.serverID]
		return {
			"channel": channel,
			"newChannel": newChannel,
			"notifyUsers": messageUsers,
			"fromServer": fromServer
		}
	
	def joinChannelNoAnnounceNotifyUsers(self, joinChannelData: Dict[str, Any]) -> List["IRCUser"]:
		"""
		Returns a list of users to notify from channel join data.
		"""
		return joinChannelData["notifyUsers"]
	
	def joinChannelNoAnnounceFinish(self, joinChannelData: Dict[str, Any]) -> None:
		"""
		Completes joining a user.
		Do it AFTER announcing.
		"""
		channel = joinChannelData["channel"]
		fromServer = joinChannelData["fromServer"]
		if joinChannelData["newChannel"]:
			self.ircd.runActionStandard("channelcreate", channel, self, channels=[channel])
		self.ircd.runActionStandard("join", channel, self, fromServer, users=[self], channels=[channel])
	
	def leaveChannel(self, channel: "IRCChannel", partType: str = "PART", typeData: Dict[Any, Any] = {}, fromServer: "IRCServer" = None) -> None:
		"""
		Removes the user from a channel. The partType and typeData are used for
		the leavemessage action to send the parting message. If the channel
		leaving is initiated by a remote server, that server should be
		specified in the fromServer parameter.
		"""
		if channel not in self.channels:
			return
		messageUsers = [u for u in channel.users.keys() if u.uuid[:3] == self.ircd.serverID]
		self.ircd.runActionProcessing("leavemessage", messageUsers, channel, self, partType, typeData, fromServer, users=[self], channels=[channel])
		self._leaveChannel(channel, partType, typeData)
	
	def _leaveChannel(self, channel: "IRCChannel", partType: str, typeData: Dict[Any, Any]) -> None:
		self.ircd.runActionStandard("leave", channel, self, partType, typeData, users=[self], channels=[channel])
		self.channels.remove(channel)
		del channel.users[self]
	
	def setModes(self, modes: List[Union[Tuple[bool, str, str], Tuple[bool, str, str, str, "datetime"]]], defaultSource: str) -> List[Tuple[bool, str, str, str, "datetime"]]:
		"""
		Sets modes on the user. Accepts modes as a list of tuples in the
		format:
		[ (adding, mode, param, setBy, setTime) ]
		- adding: True if we're setting the mode; False if unsetting
		- mode: The mode letter
		- param: The mode's parameter; None if no parameter is needed for that
		    mode
		- setBy: Optional, only used for list modes; a human-readable string
		    (typically server name or nick!user@host) for who/what set this
		    mode)
		- setTime: Optional, only used for list modes; a datetime object
		    containing when the mode was set
		
		The defaultSource is a valid user ID or server ID of someone who set
		the modes. It is used as the source for announcements about the mode
		change and as the default setter for any list modes who do not have the
		setBy parameter specified.
		The default time for list modes with no setTime specified is now().
		"""
		modeChanges = []
		defaultSourceName = self._sourceName(defaultSource)
		if defaultSourceName is None:
			raise ValueError (f"Source must be a valid user or server ID (got {defaultSource})")
		nowTime = now()
		for modeData in modes:
			mode = modeData[1]
			if mode not in self.ircd.userModeTypes:
				continue
			setBy = defaultSourceName
			setTime = nowTime
			modeType = self.ircd.userModeTypes[mode]
			adding = modeData[0]
			if modeType in (ModeType.List, ModeType.ParamOnUnset, ModeType.Param):
				param = modeData[2]
			else:
				param = None
			if modeType == ModeType.List:
				dataCount = len(modeData)
				if dataCount >= 4:
					setBy = modeData[3]
				if dataCount >= 5:
					setTime = modeData[4]
			if adding:
				paramList = self.ircd.userModes[modeType][mode].checkSet(self, param)
			else:
				paramList = self.ircd.userModes[modeType][mode].checkUnset(self, param)
			if paramList is None:
				continue
			
			for parameter in paramList:
				if self._applyMode(adding, modeType, mode, parameter, setBy, setTime):
					modeChanges.append((adding, mode, parameter, setBy, setTime))
		
		self._notifyModeChanges(modeChanges, defaultSource, defaultSourceName)
		return modeChanges
	
	def setModesByUser(self, user: "IRCUser", modes: str, params: List[str], override: bool = False) -> List[Tuple[bool, str, str, str, "datetime"]]:
		"""
		Parses a mode string specified by a user and sets those modes on the
		user.
		The user parameter should be the user who set the modes (usually, but
		not always, this user).
		The modes parameter is the actual modes string; parameters specified by
		the user should be as a list of strings in params.
		The override parameter should be used only when all permission checks
		should be overridden.
		"""
		adding = True
		changes = []
		setBy = self._sourceName(user.uuid)
		setTime = now()
		for mode in modes:
			if len(changes) >= self.ircd.config.get("modes_per_line", 20):
				break
			if mode == "+":
				adding = True
				continue
			if mode == "-":
				adding = False
				continue
			if mode not in self.ircd.userModeTypes:
				user.sendMessage(irc.ERR_UNKNOWNMODE, mode, "is unknown mode char to me")
				continue
			modeType = self.ircd.userModeTypes[mode]
			param = None
			if modeType in (ModeType.List, ModeType.ParamOnUnset) or (adding and modeType == ModeType.Param):
				try:
					param = params.pop(0)
				except IndexError:
					if modeType == ModeType.List:
						self.ircd.userModes[modeType][mode].showListParams(user, self)
					continue
			if adding:
				paramList = self.ircd.userModes[modeType][mode].checkSet(self, param)
			else:
				paramList = self.ircd.userModes[modeType][mode].checkUnset(self, param)
			if paramList is None:
				continue
			
			for parameter in paramList:
				if len(changes) >= self.ircd.config.get("modes_per_line", 20):
					break
				if not override and self.ircd.runActionUntilValue("modepermission-user-{}".format(mode), self, user, adding, parameter, users=[self, user]) is False:
					continue
				if adding:
					if modeType == ModeType.List:
						if mode in self.modes and len(self.modes[mode]) > self.ircd.config.get("user_listmode_limit", 128):
							user.sendMessage(irc.ERR_BANLISTFULL, self.name, parameter, "Channel +{} list is full".format(mode))
							continue
				if self._applyMode(adding, modeType, mode, parameter, setBy, setTime):
					changes.append((adding, mode, parameter, setBy, setTime))
		self._notifyModeChanges(changes, user.uuid, setBy)
		return changes
	
	def _applyMode(self, adding: bool, modeType: ModeType, mode: str, parameter: str, setBy: str, setTime: "datetime") -> bool:
		if parameter:
			if lenBytes(parameter) > 255:
				return False
			if " " in parameter:
				return False
		
		if adding:
			if modeType == ModeType.List:
				if mode in self.modes:
					if len(self.modes[mode]) > self.ircd.config.get("user_listmode_limit", 128):
						return False
					for paramData in self.modes[mode]:
						if parameter == paramData[0]:
							return False
				else:
					self.modes[mode] = []
				self.modes[mode].append((parameter, setBy, setTime))
				return True
			if mode in self.modes and self.modes[mode] == parameter:
				return False
			self.modes[mode] = parameter
			return True
		
		if modeType == ModeType.List:
			if mode not in self.modes:
				return False
			for index, paramData in enumerate(self.modes[mode]):
				if paramData[0] == parameter:
					del self.modes[mode][index]
					break
			else:
				return False
			if not self.modes[mode]:
				del self.modes[mode]
			return True
		if mode not in self.modes:
			return False
		if modeType == ModeType.ParamOnUnset and parameter != self.modes[mode]:
			return False
		del self.modes[mode]
		return True
	
	def _notifyModeChanges(self, modeChanges: List[Tuple[bool, str, str, str, "datetime"]], source: str, sourceName: str) -> None:
		if not modeChanges:
			return 
		for change in modeChanges:
			self.ircd.runActionStandard("modechange-user-{}".format(change[1]), self, change[3], change[0], change[2], users=[self])
		
		users = []
		if source in self.ircd.users and source[:3] == self.ircd.serverID:
			users.append(self.ircd.users[source])
		if self.uuid[:3] == self.ircd.serverID:
			users.append(self)
		if users:
			self.ircd.runActionProcessing("modemessage-user", users, self, source, sourceName, modeChanges, users=users)
		self.ircd.runActionStandard("modechanges-user", self, source, sourceName, modeChanges, users=[self])
	
	def _sourceName(self, source: str) -> str:
		if source in self.ircd.users:
			return self.ircd.users[source].hostmask()
		if source == self.ircd.serverID:
			return self.ircd.name
		if source in self.ircd.servers:
			return self.ircd.servers[source].name
		return None
	
	def modeString(self, toUser: "IRCUser") -> str:
		"""
		Get a user-reportable mode string for the modes set on the user.
		"""
		modeStr = ["+"]
		params = []
		for mode in self.modes:
			modeType = self.ircd.userModeTypes[mode]
			if modeType not in (ModeType.ParamOnUnset, ModeType.Param, ModeType.NoParam):
				continue
			if modeType != ModeType.NoParam:
				param = None
				if toUser:
					param = self.ircd.userModes[modeType][mode].showParam(toUser, self)
				if not param:
					param = self.modes[mode]
			else:
				param = None
			modeStr.append(mode)
			if param:
				params.append(param)
		if params:
			return "{} {}".format("".join(modeStr), " ".join(params))
		return "".join(modeStr)

class RemoteUser(IRCUser):
	def __init__(self, ircd: "IRCd", ip: Union["IPv4Address", "IPv6Address"], uuid: str = None, host: str = None):
		IRCUser.__init__(self, ircd, ip, uuid, host)
		self._registrationTimeoutTimer.cancel()
	
	def _startDNSResolving(self, timeout: int) -> None:
		self.register("dns", True)
	
	def sendMessage(self, command: str, *params: str, **kw: Any) -> None:
		pass # Messages can't be sent directly to remote users.
	
	def register(self, holdName: str, fromRemote: bool = False) -> None:
		"""
		Handles registration of a remote user.
		"""
		if not fromRemote:
			return
		if holdName not in self._registerHolds:
			return
		self._registerHolds.remove(holdName)
		if not self._registerHolds:
			self.ircd.log.debug("Registered remote user {user.uuid} ({userHostmask()})", user=self, userHostmask=self.hostmask)
			self.ircd.runActionStandard("remoteregister", self, users=[self])
			self.ircd.userNicks[self.nick] = self
	
	def addRegisterHold(self, holdName: str) -> None:
		pass # We're just not going to allow this here.
	
	def disconnect(self, reason: str, fromServer: "IRCServer" = None) -> None:
		"""
		Disconnects the remote user from the remote server.
		"""
		userSendList = self.disconnectDeferNotify(reason, fromServer)
		self.ircd.runActionProcessing("quitmessage", userSendList, self, reason, None, users=userSendList)
	
	def disconnectDeferNotify(self, reason: str, fromServer: "IRCServer" = None) -> List["IRCUser"]:
		"""
		Disconnects the remote user from the remote server.
		Returns the list of users to notify for manual later notification.
		"""
		if self.isRegistered():
			del self.ircd.userNicks[self.nick]
		self.ircd.recentlyQuitUsers[self.uuid] = now()
		del self.ircd.users[self.uuid]
		userSendList = []
		while self.channels:
			channel = self.channels[0]
			userSendList.extend(channel.users.keys())
			self._leaveChannel(channel, "QUIT", { "reason": reason })
		userSendList = [u for u in set(userSendList) if u.uuid[:3] == self.ircd.serverID]
		self.ircd.log.debug("Removing remote user {user.uuid} ({userHostmask()}) [from {serverID}]: {reason}", user=self, userHostmask=self.hostmask, serverID=fromServer.serverID if fromServer else "local server", reason=reason)
		self.ircd.runActionStandard("remotequit", self, reason, fromServer, users=[self], allowDisconnected=True)
		return userSendList
	
	def changeNick(self, newNick: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes the nickname of the user. If the change was initiated by a
		remote server, that server should be specified as the fromServer
		parameter.
		"""
		oldNick = self.nick
		if oldNick and oldNick in self.ircd.userNicks and self.ircd.userNicks[oldNick] == self:
			del self.ircd.userNicks[self.nick]
		self.nick = newNick
		self.ircd.userNicks[self.nick] = self
		if self.isRegistered():
			userSendList = [self]
			for channel in self.channels:
				userSendList.extend(channel.users.keys())
			userSendList = [u for u in set(userSendList) if u.uuid[:3] == self.ircd.serverID]
			self.ircd.runActionProcessing("changenickmessage", userSendList, self, oldNick, users=userSendList)
			self.ircd.runActionStandard("remotechangenick", self, oldNick, fromServer, users=[self])
	
	def changeIdent(self, newIdent: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes the ident of the user. If the change was initiated by a remote
		server, that server should be specified as the fromServer parameter.
		"""
		if lenBytes(newIdent) > self.ircd.config.get("ident_length", 12):
			return
		oldIdent = self.ident
		self.ident = newIdent
		if self.isRegistered():
			self.ircd.runActionStandard("remotechangeident", self, oldIdent, fromServer, users=[self])
	
	def changeGecos(self, newGecos: str, fromServer: "IRCServer" = None) -> None:
		"""
		Changes the real name of the user. If the change was initiated by a
		remote server, that server should be specified as the fromServer
		parameter.
		"""
		oldGecos = self.gecos
		self.gecos = newGecos
		if self.isRegistered():
			self.ircd.runActionStandard("remotechangegecos", self, oldGecos, fromServer, users=[self])
	
	def joinChannelNoAnnounceFinish(self, joinChannelData: Dict[str, Any]) -> None:
		"""
		Completes joining a user.
		Do it AFTER announcing.
		"""
		channel = joinChannelData["channel"]
		fromServer = joinChannelData["fromServer"]
		if joinChannelData["newChannel"]:
			self.ircd.runActionStandard("channelcreate", channel, self, channels=[channel])
		self.ircd.runActionStandard("remotejoin", channel, self, fromServer, users=[self], channels=[channel])
	
	def _leaveChannel(self, channel: "IRCChannel", partType: str, typeData: Dict[Any, Any]) -> None:
		self.ircd.runActionStandard("remoteleave", channel, self, partType, typeData, users=[self], channels=[channel])
		self.channels.remove(channel)
		del channel.users[self]

class LocalUser(IRCUser):
	"""
	LocalUser is a fake user created by a module, which is not
	propagated to other servers.
	"""
	def __init__(self, ircd: "IRCd", nick: str, ident: str, host: str, ip: Union["IPv4Address", "IPv6Address"], gecos: str):
		IRCUser.__init__(self, ircd, ip, None, host)
		self.localOnly = True
		self._sendMsgFunc = lambda self, command, *args, **kw: None
		self._registrationTimeoutTimer.cancel()
		self._registerHolds.clear()
		self._pinger = None
		self.nick = nick
		self.ident = ident
		self.gecos = gecos
		self.ircd.log.debug("Created new local user {user.uuid} ({userHostmask()})", user=self, userHostmask=self.hostmask)
		self.ircd.runActionStandard("localregister", self, users=[self])
		self.ircd.userNicks[self.nick] = self
	
	def _startDNSResolving(self, timeout: int) -> None:
		pass # DNS resolution shouldn't occur for fake clients
	
	def register(self, holdName: str) -> None:
		pass
	
	def setSendMsgFunc(self, func: Callable[..., None]) -> None:
		"""
		Sets the function to call when a message is sent to this user.
		"""
		self._sendMsgFunc = func
	
	def sendMessage(self, command: str, *args: str, **kw: Any) -> None:
		"""
		Sends a message to this user.
		"""
		self._sendMsgFunc(self, command, *args, **kw)
	
	def disconnect(self, reason: str) -> None:
		"""
		Cleans up and removes the user.
		"""
		del self.ircd.users[self.uuid]
		del self.ircd.userNicks[self.nick]
		userSendList = [self]
		for channel in self.channels:
			userSendList.extend(channel.users.keys())
		userSendList = [u for u in set(userSendList) if u.uuid[:3] == self.ircd.serverID]
		userSendList.remove(self)
		self.ircd.log.debug("Removing local user {user.uuid} ({userHostmask()}): {reason}", user=self, userHostmask=self.hostmask, reason=reason)
		self.ircd.runActionProcessing("quitmessage", userSendList, self, reason, None, users=userSendList)
		self.ircd.runActionStandard("localquit", self, reason, users=[self])
	
	def joinChannel(self, channel: "IRCChannel", override, bool = False) -> None:
		"""
		Joins the user to a channel.
		"""
		IRCUser.joinChannel(self, channel, True)