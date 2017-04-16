from twisted.plugin import IPlugin
from txircd.module_interface import IModuleData, ModuleData
from zope.interface import implements

class AccountAdminList(ModuleData):
	implements(IPlugin, IModuleData)
	
	name = "AccountAdminList"
	
	def actions(self):
		return [ ("statsruntype-accounts", 1, self.listAccounts) ]
	
	def listAccounts(self):
		accountNameList = self.ircd.runActionUntilValue("accountlistallnames")
		if not accountNameList:
			return {}
		accountNames = {}
		for name in accountNameList:
			accountNames[name] = "*"
		return accountNames

accountAdminList = AccountAdminList()