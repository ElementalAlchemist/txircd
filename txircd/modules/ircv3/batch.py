from twisted.plugin import IPlugin
from txircd.module_interface import IModuleData, ModuleData
from zope.interface import implementer
from typing import Any, Callable, Dict, List, Optional, Tuple
import random, string

@implementer(IPlugin, IModuleData)
class Batch(ModuleData):
	name = "Batch"
	
	def actions(self) -> List[Tuple[str, int, Callable]]:
		return [ ("startbatchsend", 10, self.startBatch),
		         ("outgoingmessagetags", 10, self.addBatchTag),
		         ("endbatchsend", 10, self.endBatch),
		         ("capabilitylist", 10, self.addCapability) ]
	
	def load(self) -> None:
		if "unloading-batch" in self.ircd.dataCache:
			del self.ircd.dataCache["unloading-batch"]
			return
		if "cap-add" in self.ircd.functionCache:
			self.ircd.functionCache["cap-add"]("batch")
	
	def unload(self) -> Optional["Deferred"]:
		self.ircd.dataCache["unloading-batch"] = True
	
	def fullUnload(self) -> Optional["Deferred"]:
		del self.ircd.dataCache["unloading-batch"]
		if "cap-del" in self.ircd.functionCache:
			self.ircd.functionCache["cap-del"]("batch")
	
	def addCapability(self, user: "IRCUser", capList: List[str]) -> None:
		capList.append("batch")
	
	def startBatch(self, user: "IRCUser", batchName: str, batchType: str, batchParameters: List[Any]) -> None:
		if "capabilities" not in user.cache or "batch" not in user.cache["capabilities"]:
			return
		uniqueReferenceTagParts = [ random.choice(string.ascii_letters) ]
		for i in range(2, 10):
			uniqueReferenceTagParts.append(random.choice(string.ascii_letters + string.digits))
		uniqueReferenceTag = "".join(uniqueReferenceTagParts)
		user.sendMessage("BATCH", "+{}".format(uniqueReferenceTag), batchType, *batchParameters, to=None)
		user.cache["currentBatch"] = uniqueReferenceTag
	
	def addBatchTag(self, user: "IRCUser", command: str, to: str, tags: Dict[str, Optional[str]]) -> None:
		if "currentBatch" in user.cache:
			tags["batch"] = user.cache["currentBatch"]
	
	def endBatch(self, user: "IRCUser", batchName: str, batchType: str, batchParameters: List[Any]) -> None:
		if "currentBatch" not in user.cache:
			return
		uniqueReferenceTag = user.cache["currentBatch"]
		del user.cache["currentBatch"]
		user.sendMessage("BATCH", "-{}".format(uniqueReferenceTag), to=None)

batch = Batch()