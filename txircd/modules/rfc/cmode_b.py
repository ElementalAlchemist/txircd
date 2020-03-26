from twisted.plugin import IPlugin
from twisted.words.protocols import irc
from txircd.module_interface import IMode, IModuleData, Mode, ModuleData
from txircd.utils import ircLower, ModeType, timestampStringFromTimeSeconds
from zope.interface import implementer
from fnmatch import fnmatchcase
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

@implementer(IPlugin, IModuleData, IMode)
class BanMode(ModuleData, Mode):
	name = "BanMode"
	core = True
	affectedActions = {
		"joinpermission": 10,
		"commandmodify-PRIVMSG": 10,
		"commandmodify-NOTICE": 10
	}
	
	def channelModes(self) -> List[Union[Tuple[str, ModeType, Mode], Tuple[str, ModeType, Mode, int, str]]]:
		return [ ("b", ModeType.List, self) ]
	
	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("modeactioncheck-channel-withuser", 100, self.checkAction),
		         ("modechange-channel-b", 1, self.onChange),
		         ("modepermission-channel-b", 1, self.checkAutostatusPermission),
		         ("userbancheck", 1, self.matchBans),
		         ("join", 10, self.populateBanCache),
		         ("join", 9, self.autoStatus),
		         ("updateuserbancache", 1, self.updateUserCaches)
		]
	
	def banMatchesUser(self, user: "IRCUser", banmask: str) -> bool:
		matchingExtban = ""
		matchNegated = False
		if ":" in banmask and ("@" not in banmask or banmask.find(":") < banmask.find("@")):
			matchingExtban, banmask = banmask.split(":", 1)
			if matchingExtban and matchingExtban[0] == "~":
				matchNegated = True
				matchingExtban = matchingExtban[1:]
		if matchingExtban:
			return self.ircd.runActionUntilTrue("usermatchban-{}".format(matchingExtban), user, matchNegated, banmask)
		return self.matchHostmask(user, banmask)
	
	def matchHostmask(self, user: "IRCUser", banmask: str) -> bool:
		banmask = ircLower(banmask)
		userMask = ircLower(user.hostmask())
		if fnmatchcase(userMask, banmask):
			return True
		userMask = ircLower(user.hostmaskWithRealHost())
		if fnmatchcase(userMask, banmask):
			return True
		userMask = ircLower(user.hostmaskWithIP())
		return fnmatchcase(userMask, banmask)
	
	def checkAction(self, actionName: str, mode: str, channel: "IRCChannel", user: "IRCUser", *params: Any, **kw: Any) -> Union[str, bool, None]:
		if "b" not in channel.modes:
			return None
		if mode == "b":
			if "b" in channel.modes:
				return "" # We'll handle the iteration
			return None
		if user in channel.users and "bans" in channel.users[user]:
			if mode in channel.users[user]["bans"]:
				return channel.users[user]["bans"][mode]
			return None
		for paramData in channel.modes["b"]:
			param = paramData[0]
			actionExtban = ""
			actionParam = ""
			if ";" in param:
				actionExtban, param = param.split(";", 1)
				if ":" in actionExtban:
					actionExtban, actionParam = actionExtban.split(":", 1)
			actionNegated = False
			if actionExtban[0] == "~":
				actionNegated = True
				actionExtban = actionExtban[1:]
			if actionExtban != mode:
				continue
			match = self.banMatchesUser(user, param)
			if match:
				if actionNegated:
					return None
				return actionParam
		return None
	
	def onChange(self, channel: "IRCChannel", source: str, adding: bool, param: str) -> None:
		if ";" in param:
			actionExtban, banmask = param.split(";", 1)
			if ":" in actionExtban:
				actionExtban, actionParam = actionExtban.split(":", 1)
			else:
				actionParam = ""
		else:
			actionExtban= ""
			actionParam = ""
			banmask = param
		if ":" in banmask and ("@" not in banmask or banmask.index(":") < banmask.index("@")):
			matchingExtban, banmask = banmask.split(":", 1)
			if matchingExtban and matchingExtban[0] == "~":
				matchNegated = True
				matchingExtban = matchingExtban[1:]
			else:
				matchNegated = False
		else:
			matchingExtban = ""
			matchNegated = None
		for user, cache in channel.users.items():
			if "bans" not in cache:
				cache["bans"] = {}
			if not (actionExtban in cache["bans"]) and not adding:
				continue # If it didn't affect them before, it won't now, so let's skip the mongo processing we're about to do to them
			if (actionExtban in cache["bans"]) and adding and actionParam == cache["bans"][actionExtban]:
				continue
			if matchingExtban:
				matchesUser = self.ircd.runActionUntilTrue("usermatchban-{}".format(matchingExtban), user, matchNegated, banmask)
			else:
				matchesUser = self.matchHostmask(user, banmask)
			if not matchesUser:
				continue
			if adding:
				cache["bans"][actionExtban] = actionParam
			else:
				del cache["bans"][actionExtban]
	
	def matchBans(self, user: "IRCUser", channel: "IRCChannel") -> Dict[str, str]:
		if user in channel.users and "bans" in channel.users[user]:
			return channel.users[user]["bans"]
		if "b" in channel.modes:
			matchesActions = {}
			for paramData in channel.modes["b"]:
				param = paramData[0]
				actionExtban = ""
				actionParam = ""
				matchingExtban = ""
				matchNegated = False
				if ";" in param:
					actionExtban, param = param.split(";", 1)
					if ":" in actionExtban:
						actionExtban, actionParam = actionExtban.split(":", 1)
				if actionExtban in matchesActions:
					continue
				if ":" in param and ("@" not in param or param.find(":") < param.find("@")):
					matchingExtban, param = param.split(":", 1)
					if matchingExtban[0] == "~":
						matchNegated = True
						matchingExtban = matchingExtban[1:]
				if matchingExtban:
					if self.ircd.runActionUntilTrue("usermatchban-{}".format(matchingExtban), user, matchNegated, param):
						matchesActions[actionExtban] = actionParam
				else:
					if self.matchHostmask(user, param):
						matchesActions[""] = ""
			return matchesActions
		return {}

	def checkAutostatusPermission(self, channel: "IRCChannel", user: "IRCUser", adding: bool, param: str) -> Optional[bool]:
		if ";" not in param:
			return None
		actionExtban = param.split(";")[0]
		if actionExtban not in self.ircd.channelStatuses:
			return None
		statusLevel = self.ircd.channelStatuses[actionExtban][1]
		if channel.userRank(user) < statusLevel and not self.ircd.runActionUntilValue("channelstatusoverride", channel, user, actionExtban, param, users=[user], channels=[channel]):
			user.sendMessage(irc.ERR_CHANOPRIVSNEEDED, channel.name, "You do not have permission to modify autostatus for mode {}".format(actionExtban))
			return False
		return None
	
	def populateBanCache(self, channel, user, fromServer = None) -> None:
		if "b" not in channel.modes:
			return
		if "bans" not in channel.users[user]:
			channel.users[user]["bans"] = {}
		for paramData in channel.modes["b"]:
			param = paramData[0]
			actionExtban = ""
			actionParam = ""
			if ";" in param:
				actionExtban, param = param.split(";", 1)
				if ":" in actionExtban:
					actionExtban, actionParam = actionExtban.split(":", 1)
			if actionExtban in channel.users[user]["bans"]:
				continue
			if self.banMatchesUser(user, param):
				channel.users[user]["bans"][actionExtban] = actionParam
	
	def autoStatus(self, channel: "IRCChannel", user: "IRCUser", fromServer: "IRCServer" = None) -> None:
		if "bans" not in channel.users[user]:
			return
		applyModes = []
		for mode in self.ircd.channelStatusOrder:
			if mode in channel.users[user]["bans"]:
				applyModes.append((True, mode, user.uuid))
		if applyModes:
			channel.setModes(applyModes, self.ircd.serverID)

	def updateUserCaches(self, user: "IRCUser") -> None:
		for channel in user.channels:
			self.populateBanCache(channel, user)
			self.autoStatus(channel, user)
	
	def banmaskHasMatchingExtban(self, banmask: str) -> bool:
		return (":" in banmask and ("@" not in banmask or banmask.find(":") < banmask.find("@")))
	
	def checkSet(self, channel: "IRCChannel", param: str) -> Optional[List[str]]:
		actionExtban = ""
		actionParam = ""
		matchingExtban = ""
		validParams = []
		for fullBanmask in param.split(","):
			banmask = fullBanmask
			if ";" in banmask:
				actionExtban, banmask = banmask.split(";", 1)
				if not actionExtban or not banmask:
					continue
				if ":" in actionExtban:
					actionExtban, actionParam = actionExtban.split(":", 1)
					if not actionParam:
						continue
				matchNegated = False
				if actionExtban[0] == "~":
					matchNegated = True
					actionExtban = actionExtban[1:]
				if actionExtban not in self.ircd.channelModeTypes:
					continue
				actionModeType = self.ircd.channelModeTypes[actionExtban]
				if actionModeType == ModeType.List:
					continue
				if actionParam and actionModeType in (ModeType.NoParam, ModeType.Status):
					continue
				if not actionParam and actionModeType == ModeType.ParamOnUnset:
					continue
				if not matchNegated and not actionParam and actionModeType == ModeType.Param:
					continue
				if actionModeType != ModeType.Status: # Don't check the parameters for status modes, but do the rest of the processing
					actionParamList = self.ircd.channelModes[actionModeType][actionExtban].checkSet(channel, actionParam)
					for actionParam in actionParamList:
						updatedBanmask = "{}:{};{}".format(actionExtban, actionParam, banmask)
						if self.banmaskHasMatchingExtban(banmask):
							matchingExtban = banmask.split(":", 1)[0]
							if not matchingExtban:
								continue
						else:
							if "!" not in banmask:
								updatedBanmask = "{}!*@*".format(updatedBanmask)
							elif "@" not in banmask:
								updatedBanmask = "{}@*".format(updatedBanmask)
						validParams.append(updatedBanmask)
					continue
			if self.banmaskHasMatchingExtban(banmask):
				matchingExtban = banmask.split(":", 1)[0]
				if not matchingExtban:
					continue
			else:
				if "!" not in banmask:
					fullBanmask = "{}!*@*".format(fullBanmask) # Append it to the param since it needs to go to output (and banmask is at the trailing end of param so it's OK)
				elif "@" not in banmask:
					fullBanmask = "{}@*".format(fullBanmask)
			validParams.append(fullBanmask)
		return validParams
	
	def checkUnset(self, channel: "IRCChannel", param: str) -> Optional[List[str]]:
		actionExtban = ""
		validParams = []
		for fullBanmask in param.split(","):
			banmask = fullBanmask
			if ";" in banmask:
				actionExtban, banmask = banmask.split(";", 1)
				if actionExtban in self.ircd.channelModeTypes:
					actionModeType = self.ircd.channelModeTypes[actionExtban]
					if actionModeType == ModeType.Status:
						if self.banmaskHasMatchingExtban(banmask):
							validParams.append(fullBanmask)
						elif "!" not in banmask:
							fullBanmask = "{}!*@*".format(fullBanmask)
						elif "@" not in banmask:
							fullBanmask = "{}@*".format(fullBanmask)
						validParams.append(fullBanmask)
					else:
						actionParam = None
						if ":" in actionExtban:
							actionExtban, actionParam = actionExtban.split(":", 1)
						actionParamList = self.ircd.channelModes[actionModeType][actionExtban].checkUnset(channel, actionParam)
						for actionParam in actionParamList:
							updatedBanmask = "{}:{};{}".format(actionExtban, actionParam, banmask)
							if self.banmaskHasMatchingExtban(banmask):
								validParams.append(updatedBanmask)
								continue
							if "!" not in banmask:
								updatedBanmask = "{}!*@*".format(updatedBanmask)
							elif "@" not in banmask:
								updatedBanmask = "{}@*".format(updatedBanmask)
							validParams.append(updatedBanmask)
				else:
					validParams.append(fullBanmask) # If the mode module was unloaded, just let it out of the system
			else:
				if self.banmaskHasMatchingExtban(banmask):
					validParams.append(fullBanmask)
					continue # Just allow this; the other checks will be managed by checking whether the parameter is actually set on the channel
				# If there's no matching extban, make sure the ident and host are given
				if "!" not in banmask:
					fullBanmask = "{}!*@*".format(fullBanmask)
				elif "@" not in banmask:
					fullBanmask = "{}@*".format(fullBanmask)
			
			# Make ban unsetting case-insensitive
			lowerBanmask = ircLower(fullBanmask)
			for existingParamData in channel.modes["b"]:
				if ircLower(existingParamData[0]) == lowerBanmask:
					validParams.append(existingParamData[0])
					break
			else:
				validParams.append(fullBanmask)
		return validParams
	
	def apply(self, actionType: str, channel: "IRCChannel", param: str, *params: Any) -> Union[Optional[bool], None]: # Union of return types for each affected action
		if actionType == "joinpermission":
			actionChannel, user = params
			# When we get in this function, the user is trying to join, so the cache will always either not exist or be invalid
			# so we'll go straight to analyzing the ban list
			if "b" not in channel.modes:
				return None
			for paramData in channel.modes["b"]:
				param = paramData[0]
				if ";" in param:
					continue # Ignore entries with action extbans
				if self.banMatchesUser(user, param):
					user.sendMessage(irc.ERR_BANNEDFROMCHAN, channel.name, "Cannot join channel (You're banned)")
					return False
			return None
		if actionType in ("commandmodify-PRIVMSG", "commandmodify-NOTICE"):
			messagingUser, data = params
			if channel not in data["targetchans"]:
				return
			if messagingUser in channel.users: # We're only applying this to users not in the channel
				return
			for paramData in channel.modes["b"]:
				param = paramData[0]
				if ";" in param:
					continue # We don't care about action extbans here
				if self.banMatchesUser(user, param):
					user.sendMessage(irc.ERR_BANNEDFROMCHAN, channel.name, "Cannot send message to channel (You're banned)")
					del data["targetchans"][channel]
					return
	
	def showListParams(self, user: "IRCUser", channel: "IRCChannel") -> None:
		if user not in channel.users or "b" not in channel.modes:
			user.sendMessage(irc.RPL_ENDOFBANLIST, channel.name, "End of channel ban list")
			return
		for paramData in channel.modes["b"]:
			user.sendMessage(irc.RPL_BANLIST, channel.name, paramData[0], paramData[1], timestampStringFromTimeSeconds(paramData[2]))
		user.sendMessage(irc.RPL_ENDOFBANLIST, channel.name, "End of channel ban list")

banMode = BanMode()