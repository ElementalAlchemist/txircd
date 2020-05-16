from twisted.internet.task import LoopingCall
from twisted.plugin import IPlugin
from twisted.python.logfile import DailyLogFile
from txircd.config import ConfigValidationError
from txircd.module_interface import IModuleData, ModuleData
from txircd.utils import CaseInsensitiveDictionary, now
from zope.interface import implementer
from fnmatch import fnmatchcase
from typing import Any, Callable, Dict, List, Tuple

@implementer(IPlugin, IModuleData)
class ChannelLog(ModuleData):
	name = "ChannelLog"
	
	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("commandextra-PRIVMSG", 1, self.logMsg),
			("commandextra-NOTICE", 1, self.logNotice),
			("servercommandextra-PRIVMSG", 1, self.logMsgServer),
			("servercommandextra-NOTICE", 1, self.logNoticeServer),
			("join", 1, self.logJoin),
			("remotejoin", 1, self.logJoin),
			("leave", 1, self.logLeave),
			("remoteleave", 1, self.logLeave),
			("topic", 1, self.logTopic),
			("modechanges-channel", 1, self.logModeChanges) ]
	
	def load(self) -> None:
		self.logFiles = CaseInsensitiveDictionary()
		self.cleanupProcess = LoopingCall(self.cleanLogFiles)
		self.cleanupProcess.start(600, now=False)
	
	def unload(self) -> None:
		for logFile in self.logFiles.values():
			logFile.close()
		self.logFiles.clear()
		if self.cleanupProcess.running:
			self.cleanupProcess.stop()
	
	def verifyConfig(self, config: Dict[str, Any]) -> None:
		if "channel_log_directory" in config:
			if not isinstance(config["channel_log_directory"], str):
				raise ConfigValidationError("channel_log_directory", "must be a string representing the directory")
		if "channel_log_channels" in config:
			if not isinstance(config["channel_log_channels"], list):
				raise ConfigValidationError("channel_log_channels", "must be a list of channel masks")
			for channelNameMask in config["channel_log_channels"]:
				if not isinstance(channelNameMask, str):
					raise ConfigValidationError("channel_log_channels", "must be a list of channel masks")
	
	def cleanLogFiles(self) -> None:
		deadChannelNames = {}
		for channelName, logFile in self.logFiles.items():
			if channelName not in self.ircd.channels:
				deadChannelNames[channelName] = logFile
		for channelName, logFile in deadChannelNames.items():
			logFile.close()
			del self.logFiles[channelName]
	
	def timestampPrefix(self) -> str:
		nowTime = now()
		return "[{}:{:02d}:{:02d}]".format(nowTime.hour, nowTime.minute, nowTime.second)
	
	def logLine(self, channel: "IRCChannel", line: str) -> None:
		line = "{} {}\n".format(self.timestampPrefix(), line)
		if channel.name in self.logFiles:
			logFile = self.logFiles[channel.name]
		else:
			if not self.shouldLogChannel(channel):
				return
			logFile = DailyLogFile(channel.name, self.ircd.config.get("channel_log_directory", ""))
			self.logFiles[channel.name] = logFile
		if logFile.shouldRotate():
			logFile.rotate()
		logFile.write(line)
	
	def shouldLogChannel(self, channel: "IRCChannel"):
		channelNameMaskList = self.ircd.config.get("channel_list_channels", [])
		if not channelNameMaskList:
			return True
		channelName = channel.name
		for channelNameMask in channelNameMaskList:
			if fnmatchcase(channelName, channelNameMask):
				return True
		return False
	
	def logMsg(self, user: "IRCUser", data: Dict[Any, Any]) -> None:
		if "targetchans" not in data:
			return
		for channel, message in data["targetchans"].items():
			if message[:7] == "\x01ACTION":
				message = message[8:]
				if message[-1] == "\x01":
					message = message[:-1]
				self.logLine(channel, "*{} {}".format(user.nick, message))
				continue
			self.logLine(channel, "<{}> {}".format(user.nick, message))
	
	def logNotice(self, user: "IRCUser", data: Dict[Any, Any]) -> None:
		if "targetchans" not in data:
			return
		for channel, message in data["targetchans"].items():
			self.logLine(channel, "--{}-- {}".format(user.nick, message))
	
	def logMsgServer(self, server: "IRCServer", data: Dict[Any, Any]) -> None:
		if "tochan" not in data:
			return
		fromUser = data["from"]
		channel = data["tochan"]
		message = data["message"]
		if message[:7] == "\x01ACTION":
			message = message[8:]
			if message[-1] == "\x01":
				message = message[:-1]
			self.logLine(channel, "*{} {}".format(fromUser.nick, message))
		else:
			self.logLine(channel, "<{}> {}".format(fromUser.nick, message))
	
	def logNoticeServer(self, server: "IRCServer", data: Dict[Any, Any]) -> None:
		if "tochan" not in data:
			return
		self.logLine(data["tochan"], "--{}-- {}".format(data["from"].nick, data["message"]))
	
	def logJoin(self, channel: "IRCChannel", user: "IRCUser", fromServer: "IRCServer" = None) -> None:
		self.logLine(channel, "> {} has joined {}".format(user.nick, channel.name))
	
	def logLeave(self, channel: "IRCChannel", user: "IRCUser", partType: str, typeData: Dict[str, Any]) -> None:
		if partType == "QUIT":
			self.logLine(channel, "> {} has quit: {}".format(user.nick, typeData["reason"]))
		elif partType == "KICK":
			self.logLine(channel, "> {} has been kicked from {} by {}: {}".format(user.nick, channel.name, typeData["user"].nick if typeData["byuser"] else typeData["server"].name, typeData["reason"]))
		else:
			if "reason" in typeData and typeData["reason"]:
				self.logLine(channel, "> {} has left {}: {}".format(user.nick, channel.name, typeData["reason"]))
			else:
				self.logLine(channel, "> {} has left {}".format(user.nick, channel.name))
	
	def logTopic(self, channel: "IRCChannel", setter: str, source: str, oldTopic: str) -> None:
		self.logLine(channel, "> {} changed the channel topic: {}".format(source, channel.topic))
	
	def logModeChanges(self, channel: "IRCChannel", source: str, sourceName: str, modeChanges: List[Tuple[bool, str, str, str, "datetime"]]) -> None:
		modes = []
		params = []
		lastAdding = None
		for modeChangeData in modeChanges:
			if lastAdding != modeChangeData[0]:
				if modeChangeData[0]:
					modes.append("+")
					lastAdding = True
				else:
					modes.append("-")
					lastAdding = False
			modes.append(modeChangeData[1])
			if modeChangeData[2]:
				params.append(modeChangeData[2])
		modeChangeStr = "{} {}".format("".join(modes), " ".join(params)) if params else "".join(modes)
		self.logLine(channel, "> {} has set modes {}".format(sourceName, modeChangeStr))

channelLog = ChannelLog()