from twisted.plugin import IPlugin
from txircd.config import ConfigValidationError
from txircd.module_interface import IModuleData, ModuleData
from txircd.utils import ipAddressToShow
from zope.interface import implementer
from ipaddress import ip_address
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

@implementer(IPlugin, IModuleData)
class ConnectionLimit(ModuleData):
	name = "ConnectionLimit"
	peerConnections = {}

	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("userconnect", 100, self.handleLocalConnect),
		         ("remoteregister", 100, self.handleRemoteConnect),
		         ("quit", 100, self.handleDisconnect),
		         ("remotequit", 100, self.handleDisconnect),
		         ("changeipaddress", 100, self.handleIPAddressChange) ]

	def load(self) -> None:
		for user in self.ircd.users.values():
			if not user.localOnly:
				self.addToConnections(ipAddressToShow(user.ip))

	def verifyConfig(self, config: Dict[str, Any]) -> None:
		if "connlimit_globmax" in config and (not isinstance(config["connlimit_globmax"], int) or config["connlimit_globmax"] < 0):
			raise ConfigValidationError("connlimit_globmax", "invalid number")
		if "connlimit_whitelist" in config:
			if not isinstance(config["connlimit_whitelist"], list):
				raise ConfigValidationError("connlimit_whitelist", "value must be a list")
			for ip in config["connlimit_whitelist"]:
				try:
					ip_address(ip)
				except ValueError:
					raise ConfigValidationError("connlimit_whitelist", "every entry must be a valid ip")

	def handleLocalConnect(self, user: "IRCUser", *params: Any) -> Optional[bool]:
		ip = ipAddressToShow(user.ip)
		if self.addToConnections(ip) and self.peerConnections[ip] > self.ircd.config.get("connlimit_globmax", 3):
			self.ircd.log.info("Connection limit reached from {ip}", ip=ip)
			user.disconnect("No more connections allowed from your IP ({})".format(ip))
			return None
		return True

	def handleRemoteConnect(self, user: "IRCUser", *params: Any) -> None:
		self.addToConnections(ipAddressToShow(user.ip))

	def handleDisconnect(self, user: "IRCUser", *params: Any) -> None:
		ip = ipAddressToShow(user.ip)
		self.removeConnection(ip)
	
	def handleIPAddressChange(self, user: "IRCUser", oldIP: Union["IPv4Address", "IPv6Address"]) -> None:
		self.removeConnection(ipAddressToShow(oldIP))
		self.addToConnections(ipAddressToShow(user.ip))

	def addToConnections(self, ip: str) -> bool:
		if ip in self.ircd.config.get("connlimit_whitelist", []):
			return False
		if ip in self.peerConnections:
			self.peerConnections[ip] += 1
		else:
			self.peerConnections[ip] = 1
		return True
	
	def removeConnection(self, ip: str) -> None:
		if ip in self.peerConnections:
			self.peerConnections[ip] -= 1
			if self.peerConnections[ip] < 1:
				del self.peerConnections[ip]

connLimit = ConnectionLimit()