from twisted.plugin import IPlugin
from twisted.words.protocols import irc
from txircd.module_interface import Command, ICommand, IModuleData, ModuleData
from txircd.utils import splitMessage
from zope.interface import implements

irc.ERR_INVALIDCAPCMD = "410"

class Cap(ModuleData, Command):
	implements(IPlugin, IModuleData, ICommand)
	
	name = "Cap"
	forRegistered = None
	
	def actions(self):
		return [ ("capabilitylist", 10, self.listCapability) ]
	
	def userCommands(self):
		return [ ("CAP", 1, self) ]
	
	def load(self):
		self.ircd.functionCache["cap-add"] = self.newCapability
		self.ircd.functionCache["cap-del"] = self.removeCapability
		self.newCapability("cap-notify")
		for user in self.ircd.users.itervalues():
			if "capversion" in user.cache and user.cache["capversion"] >= 302:
				if "capabilities" not in user.cache:
					user.cache["capabilities"] = {}
				user.cache["capabilities"]["cap-notify"] = None
	
	def unload(self):
		self.removeCapability("cap-notify")
		del self.ircd.functionCache["cap-add"]
		del self.ircd.functionCache["cap-del"]
	
	def listCapability(self, capList):
		capList.append("cap-notify")
	
	def newCapability(self, capName, sendInBatch = None):
		for user in self.ircd.users.itervalues():
			if "capabilities" in user.cache and "cap-notify" in user.cache["capabilities"]:
				if sendInBatch:
					user.sendMessageInBatch(sendInBatch, "CAP", "NEW", capName)
				else:
					user.sendMessage("CAP", "NEW", capName)
	
	def removeCapability(self, capability, sendInBatch = None):
		if "=" in capability:
			capName, value = capability.split("=", 1)
		else:
			capName = capability
			value = None
		for user in self.ircd.users.itervalues():
			if "capabilities" in user.cache:
				if "cap-notify" in user.cache["capabilities"]:
					if sendInBatch:
						user.sendMessageInBatch(sendInBatch, "CAP", "DEL", capName)
					else:
						user.sendMessage("CAP", "DEL", capName)
				if capName in user.cache["capabilities"] and (value is None or user.cache["capabilities"][capName] == value):
					del user.cache["capabilities"][capName]
	
	def parseParams(self, user, params, prefix, tags):
		if not params:
			user.sendSingleError("CapParams", irc.ERR_NEEDMOREPARAMS, "CAP", "Not enough parameters")
			return None
		subcmd = params[0].upper()
		if subcmd == "LS":
			if len(params) == 1:
				return {
					"subcmd": "LS"
				}
			return {
				"subcmd": "LS",
				"version": params[1]
			}
		if subcmd == "LIST":
			return {
				"subcmd": "LIST"
			}
		if subcmd == "REQ":
			if len(params) < 2:
				user.sendSingleError("CapReqParams", irc.ERR_INVALIDCAPCMD, "REQ", "Missing request list")
				return None
			return {
				"subcmd": "REQ",
				"capabilities": params[1].split(" ")
			}
		if subcmd == "END":
			return {
				"subcmd": "END"
			}
		user.sendSingleError("CapSubcmd", irc.ERR_INVALIDCAPCMD, subcmd, ":Invalid subcommand")
		return None
	
	def execute(self, user, data):
		subCmd = data["subcmd"]
		if not user.isRegistered():
			user.addRegisterHold("CAP")
		if "capabilities" not in user.cache:
			user.cache["capabilities"] = {}
		
		if subCmd == "LS":
			if "version" in data:
				version = data["version"]
				if version == "302":
					user.cache["capversion"] = 302
					user.cache["capabilities"]["cap-notify"] = None
			capList = []
			self.ircd.runActionStandard("capabilitylist", user, capList)
			capabilities = " ".join(capList)
			splitCapabilities = splitMessage(capabilities, 400)
			if splitCapabilities:
				if "capversion" not in user.cache:
					user.sendMessage("CAP", "LS", splitCapabilities[0]) # We can only send one line to 3.1 clients
				else:
					for line in splitCapabilities[:-1]:
						user.sendMessage("CAP", "LS", "*", line)
					user.sendMessage("CAP", "LS", splitCapabilities[-1])
			return True
		if subCmd == "LIST":
			capabilities = ""
			if "capabilities" in user.cache:
				capabilities = " ".join(user.cache["capabilities"].keys())
			user.sendMessage("CAP", "LIST", capabilities)
			return True
		if subCmd == "REQ":
			allCapabilities = []
			self.ircd.runActionStandard("capabilitylist", user, allCapabilities)
			allCapabilities = [ capability.split("=")[0] for capability in allCapabilities ]
			requestedCapabilities = data["capabilities"]
			changes = []
			changeRejected = False
			for capability in requestedCapabilities:
				capability = capability.lower()
				if capability[0] == "-":
					capability = capability[1:]
					if not capability:
						changeRejected = True # It's not OK to do that to us. :(
						break
					if capability not in allCapabilities:
						changeRejected = True
						break
					removeIsOK = self.ircd.runActionUntilValue("checkremovecapability", user, capability)
					if removeIsOK is False:
						changeRejected = True
						break
					changes.append((False, capability))
					continue
				if capability not in allCapabilities:
					changeRejected = True
					break
				addIsOK = self.ircd.runActionUntilValue("checkaddcapability", user, capability)
				if addIsOK is False:
					changeRejected = True
					break
				changes.append((True, capability))
			if changeRejected:
				user.sendMessage("CAP", "NAK", " ".join(requestedCapabilities))
				return True
			if "capabilities" not in user.cache:
				user.cache["capabilities"] = {}
			for change in changes:
				if change[0]:
					if "=" in change:
						capAndValue = change[1].split("=", 1)
						capability = capAndValue[0]
						value = capAndValue[1]
					else:
						capability = change[1]
						value = None
					user.cache["capabilities"][change[1]] = value
					self.ircd.runActionStandard("addusercap", user, change[1], value)
				elif change[1] in user.cache["capabilities"]:
					del user.cache["capabilities"][change[1]]
					self.ircd.runActionStandard("delusercap", user, change[1])
			user.sendMessage("CAP", "ACK", " ".join(requestedCapabilities))
			return True
		if subCmd == "END":
			user.register("CAP")
			return True
		return None

capCmd = Cap()