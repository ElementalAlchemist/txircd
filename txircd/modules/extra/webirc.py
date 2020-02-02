from twisted.names import client as dnsClient
from twisted.plugin import IPlugin
from twisted.words.protocols import irc
from txircd.config import ConfigValidationError
from txircd.module_interface import Command, ICommand, IModuleData, ModuleData
from txircd.utils import ipAddressToShow, isValidHost, lenBytes
from zope.interface import implementer
from ipaddress import ip_address
from typing import Any, Callable, Dict, List, Optional, Tuple

@implementer(IPlugin, IModuleData, ICommand)
class WebIRC(ModuleData, Command):
	name = "WebIRC"
	forRegistered = False
	
	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("commandpermission-WEBIRC", 10, self.checkSourceAndPass) ]
	
	def userCommands(self) -> List[Tuple[str, int, Command]]:
		return [ ("WEBIRC", 1, self) ]
	
	def verifyConfig(self, config: Dict[str, Any]) -> None:
		if "webirc_allowed_sources" in config:
			if not isinstance(config["webirc_allowed_sources"], dict):
				raise ConfigValidationError("webirc_allowed_sources", "value must be a dictionary")
			for ip, password in config["webirc_allowed_sources"].items():
				if not isinstance(ip, str):
					raise ConfigValidationError("webirc_allowed_sources", "ip value must be a string")
				if not isinstance(password, str):
					raise ConfigValidationError("webirc_allowed_sources", "password value must be a string")
	
	def checkSourceAndPass(self, user: "IRCUser", data: Dict[Any, Any]) -> Optional[bool]:
		entry = None
		if ipAddressToShow(user.ip) in self.ircd.config.get("webirc_allowed_sources", {}):
			entry = ipAddressToShow(user.ip)
		if entry is None and user.realHost in self.ircd.config.get("webirc_allowed_sources", {}):
			entry = user.realHost
		if entry is None:
			self.ircd.log.warn("WEBIRC was requested from IP \"{ip}\" and host \"{user.realHost}\", but the IP and host do not match any WEBIRC configuration.", user=user, ip=ipAddressToShow(user.ip))
			return False
		if self.ircd.config["webirc_allowed_sources"][entry] != data["password"]:
			self.ircd.log.warn("WEBIRC was requested from IP \"{ip}\" and host \"{user.realHost}\" with password \"{password}\", but this password does not match the WEBIRC configuration for this IP.", user=user, ip=ipAddressToShow(user.ip), password=data)
			return False
		return None
	
	def parseParams(self, user: "IRCUser", params: List[str], prefix: str, tags: Dict[str, Optional[str]]) -> Optional[Dict[Any, Any]]:
		if len(params) < 4:
			user.sendSingleError("WebircCmd", irc.ERR_NEEDMOREPARAMS, "WEBIRC", "Not enough parameters")
			return None
		return { # We don't need params[1]; this is the client name which we don't use.
			"password": params[0],
			"host": params[2],
			"ip": params[3]
		}
	
	def execute(self, user: "IRCUser", data: Dict[Any, Any]) -> bool:
		# We verify that the DNS resolution is correct and set the provided IP as the host if it is incorrect.
		host = data["host"]
		requestIP = data["ip"]
		maxLength = self.ircd.config.get("hostname_length", 64)
		if not isValidHost(host) or lenBytes(host) > maxLength:
			self.useIPFallback(user, host, requestIP)
			return True
		user.addRegisterHold("WEBIRC")
		resolveDeferred = dnsClient.getHostByName(host, timeout=(2,))
		resolveDeferred.addCallbacks(callback=self.checkDNS, callbackArgs=(user, host, requestIP), errback=self.failedDNS, errbackArgs=(user, host, requestIP))
		return True
	
	def checkDNS(self, result: str, user: "IRCUser", host: str, requestIP: str) -> None:
		if result == requestIP:
			self.ircd.log.info("WEBIRC detected for IP \"{userip}\"; changing {user.uuid}'s IP to \"{requestip}\" and their real host to \"{requesthost}\".", user=user, userip=ipAddressToShow(user.ip), requestip=requestIP, requesthost=host)
			user.changeIP(ip_address(requestIP))
			user.realHost = host
			user.register("WEBIRC")
			return
		self.useIPFallback(user, host, requestIP)
	
	def failedDNS(self, error: "Failure", user: "IRCUser", host: str, requestIP: str) -> None:
		self.useIPFallback(user, host, requestIP)
		user.register("WEBIRC")
	
	def useIPFallback(self, user: "IRCUser", host: str, requestIP: str) -> None:
		self.ircd.log.warn("DNS resolution for WEBIRC command from IP \"{userip}\" with requested IP \"{requestip}\" and requested host \"{requesthost}\" has failed; using the requested IP address as the host instead.", user=user, userip=ipAddressToShow(user.ip), requestip=requestIP, requesthost=host)
		user.ip = ip_address(requestIP)
		user.realHost = requestIP

webirc = WebIRC()