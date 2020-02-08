from twisted.plugin import IPlugin
from twisted.words.protocols import irc
from txircd.channel import InvalidChannelNameError, IRCChannel
from txircd.module_interface import Command, ICommand, IModuleData, ModuleData
from zope.interface import implementer
from typing import Any, Callable, Dict, List, Optional, Tuple

@implementer(IPlugin, IModuleData)
class JoinCommand(ModuleData):
	name = "JoinCommand"
	core = True
	
	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("join", 20, self.broadcastJoin),
		         ("remotejoin", 20, self.broadcastJoin),
		         ("joinmessage", 1, self.sendJoinMessage) ]
	
	def userCommands(self) -> List[Tuple[str, int, Command]]:
		return [ ("JOIN", 1, JoinChannel(self.ircd)) ]
	
	def serverCommands(self) -> List[Tuple[str, int, Command]]:
		return [ ("JOIN", 1, ServerJoin(self.ircd)) ]
	
	def sendJoinMessage(self, messageUsers: List["IRCUser"], channel: "IRCChannel", user: "IRCUser", batchName: Optional[str]) -> None:
		userPrefix = user.hostmask()
		conditionalTags = {}
		self.ircd.runActionStandard("sendingusertags", user, conditionalTags)
		for destUser in messageUsers:
			tags = destUser.filterConditionalTags(conditionalTags)
			if batchName is None:
				destUser.sendMessage("JOIN", to=channel.name, prefix=userPrefix, tags=tags)
			else:
				destUser.sendMessageInBatch(batchName, "JOIN", to=channel.name, prefix=userPrefix, tags=tags)
		del messageUsers[:]
	
	def broadcastJoin(self, channel: "IRCChannel", user: "IRCUser", fromServer: Optional["IRCServer"]) -> None:
		self.ircd.broadcastToServers(fromServer, "JOIN", channel.name, prefix=user.uuid)

@implementer(ICommand)
class JoinChannel(Command):
	def __init__(self, ircd):
		self.ircd = ircd
	
	def parseParams(self, user: "IRCUser", params: List[str], prefix: str, tags: Dict[str, Optional[str]]) -> Optional[Dict[Any, Any]]:
		if not params or not params[0]:
			user.sendSingleError("JoinCmd", irc.ERR_NEEDMOREPARAMS, "JOIN", "Not enough parameters")
			return None
		joiningChannels = params[0].split(",")
		chanKeys = params[1].split(",") if len(params) > 1 else []
		while len(chanKeys) < len(joiningChannels):
			chanKeys.append("")
		user.startErrorBatch("JoinCmd")
		removeIndices = []
		for index, chanName in enumerate(joiningChannels):
			if not chanName:
				user.sendBatchedError("JoinCmd", irc.ERR_BADCHANMASK, "*", "Bad channel mask")
				removeIndices.append(index)
			elif chanName[0] != "#":
				user.sendBatchedError("JoinCmd", irc.ERR_BADCHANMASK, chanName, "Bad channel mask")
				removeIndices.append(index)
		removeIndices.sort()
		removeIndices.reverse() # Put the indices to remove in reverse order so we don't have to finagle with them on removal
		for index in removeIndices:
			del joiningChannels[index]
			del chanKeys[index]
		if not joiningChannels:
			return None
		channels = []
		for chan in joiningChannels:
			try:
				channels.append(self.ircd.channels[chan] if chan in self.ircd.channels else IRCChannel(self.ircd, chan))
			except InvalidChannelNameError:
				user.sendBatchedError("JoinCmd", irc.ERR_BADCHANMASK, chanName, "Bad channel mask")
		return {
			"channels": channels,
			"keys": chanKeys
		}
	
	def affectedChannels(self, user: "IRCUser", data: Dict[Any, Any]) -> List["IRCChannel"]:
		return data["channels"]
	
	def execute(self, user: "IRCUser", data: Dict[Any, Any]) -> bool:
		for channel in data["channels"]:
			user.joinChannel(channel)
		return True

@implementer(ICommand)
class ServerJoin(Command):
	burstQueuePriority = 80
	
	def __init__(self, ircd):
		self.ircd = ircd
	
	def parseParams(self, server: "IRCServer", params: List[str], prefix: str, tags: Dict[str, Optional[str]]) -> Optional[Dict[Any, Any]]:
		if len(params) != 1:
			return None
		if prefix not in self.ircd.users:
			if prefix in self.ircd.recentlyQuitUsers:
				return {
					"lostuser": True
				}
			return None
		try:
			return {
				"user": self.ircd.users[prefix],
				"channel": self.ircd.channels[params[0]] if params[0] in self.ircd.channels else IRCChannel(self.ircd, params[0])
			}
		except ValueError:
			return None
	
	def execute(self, server: "IRCServer", data: Dict[Any, Any]) -> bool:
		if "lostuser" not in data:
			data["user"].joinChannel(data["channel"], True, server)
		return True

joinCommand = JoinCommand()
