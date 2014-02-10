from twisted.application.service import Service
from twisted.internet import reactor
from twisted.internet.defer import DeferredList
from twisted.internet.endpoints import serverFromString
from twisted.plugin import getPlugins
from twisted.python import log
from txircd.config import Config
from txircd.factory import ServerListenFactory, UserFactory
from txircd.module_interface import ICommand, IMode, IModuleData
from txircd.utils import ModeType, unescapeEndpointDescription
import logging, shelve, txircd.modules

class IRCd(Service):
    def __init__(self, configFileName):
        self.config = Config(configFileName)
        self.boundPorts = {}
        self.loadedModules = {}
        self._loadedModuleData = {}
        self.commonModules = set()
        self.userCommands = {}
        self.serverCommands = {}
        self.channelModes = ({}, {}, {}, {})
        self.channelStatuses = {}
        self.channelStatusSymbols = {}
        self.channelStatusOrder = []
        self.channelModeTypes = {}
        self.userModes = ({}, {}, {}, {})
        self.userModeTypes = {}
        self.actions = {}
        self.storage = None
    
    def startService(self):
        log.msg("Loading storage...", logLevel=logging.INFO)
        self.storage = shelve.open("data")
        log.msg("Loading modules...", logLevel=logging.INFO)
        self._loadModules()
        log.msg("Binding ports...", logLevel=logging.INFO)
        self._bindPorts()
        log.msg("txircd started!", logLevel=logging.INFO)
    
    def stopService(self):
        stopDeferreds = []
        log.msg("Unloading modules...", logLevel=logging.INFO)
        moduleList = self.loadedModules.keys()
        for module in moduleList:
            self.unloadModule(moduleList, False) # Incomplete unload is done to save time and because side effects are destroyed anyway
        log.msg("Closing data storage...", logLevel=logging.INFO)
        self.storage.close()
        log.msg("Releasing ports...", logLevel=logging.INFO)
        stopDeferreds.extend(self._unbindPorts())
        return DeferredList(stopDeferreds)
    
    def _loadModules(self):
        for module in getPlugins(IModuleData, txircd.modules):
            if module.name in self.loadedModules:
                continue
            if module.core or module.name in self.config["modules"]:
                self._loadModuleData(module)
    
    def loadModule(self, moduleName):
        for module in getPlugins(IModuleData, txircd.modules):
            if module.name == moduleName:
                self._loadModuleData(module)
                break
    
    def _loadModuleData(self, module):
        if not IModuleData.providedBy(module):
            raise ModuleLoadError ("???", "Module does not implement module interface")
        if not module.name:
            raise ModuleLoadError ("???", "Module did not provide a name")
        if module.name in self.loadedModules:
            return
        module.hookIRCd(self)
        moduleData = {
            "channelmodes": module.channelModes(),
            "usermodes": module.userModes(),
            "actions": module.actions(),
            "usercommands": module.userCommands(),
            "servercommands": module.serverCommands()
        }
        newChannelModes = ({}, {}, {}, {})
        newChannelStatuses = {}
        newUserModes = ({}, {}, {}, {})
        newActions = {}
        newUserCommands = {}
        newServerCommands = {}
        common = False
        for mode in moduleData["channelmodes"]:
            if mode[0] in self.channelModeTypes:
                raise ModuleLoadError (module.name, "Tries to implement channel mode +{} when that mode is already implemented.".format(mode[0]))
            if not IMode.providedBy(mode[2]):
                raise ModuleLoadError (module.name, "Returns a channel mode object (+{}) that doesn't implement IMode.".format(mode[0]))
            if mode[1] == ModeType.Status:
                if mode[4] in self.channelStatusSymbols:
                    raise ModuleLoadError (module.name, "Tries to create a channel rank with symbol {} when that symbol is already in use.".format(mode[4]))
                try:
                    newChannelStatuses[mode[0]] = (mode[4], mode[3], mode[2])
                except IndexError:
                    raise ModuleLoadError (module.name, "Specifies channel status mode {} without a rank or symbol".format(mode[0]))
            else:
                newChannelModes[mode[1]][mode[0]] = mode[2]
            common = True
        for mode in moduleData["usermodes"]:
            if mode[0] in self.userModeTypes:
                raise ModuleLoadError (module.name, "Tries to implement user mode +{} when that mode is already implemented.".format(mode[0]))
            if not IMode.providedBy(mode[2]):
                raise ModuleLoadError (module.name, "Returns a user mode object (+{}) that doesn't implement IMode.".format(mode[0]))
            newUserModes[mode[1]][mode[0]] = mode[2]
            common = True
        for action in moduleData["actions"]:
            if action[0] not in newActions:
                newActions[action[0]] = (action[2], action[1])
        for command in moduleData["usercommands"]:
            if command[0] not in newUserCommands:
                newUserCommands[command[0]] = []
            if not ICommand.providedBy(command[2]):
                raise ModuleLoadError (module.name, "Returns a user command object ({}) that doesn't implement ICommand.".format(command[0]))
            newUserCommands[command[0]].append((command[2], command[1]))
        for command in moduleData["servercommands"]:
            if command[0] not in newServerCommands:
                newServerCommands[command[0]] = []
            if not ICommand.providedBy(command[2]):
                raise ModuleLoadError (module.name, "Returns a server command object ({}) that doesnt implement ICommand.".format(command[0]))
            newServerCommands[command[0]].append((command[2], command[1]))
            common = True
        if not common:
            common = module.requiredOnAllServers
        
        self.loadedModules[module.name] = module
        self._loadedModuleData[module.name] = moduleData
        if common:
            self.commonModules.add(module.name)
        
        if "moduleload" in self.actions:
            for action in self.actions["moduleload"]:
                action(module.name)
        
        for type, typeSet in enumerate(newChannelModes):
            for mode, implementation in typeSet.iteritems():
                self.channelModeTypes[mode] = type
                self.channelModes[type][mode] = implementation
        for mode, data in newChannelStatuses.iteritems():
            self.channelModeTypes[mode] = ModeType.Status
            self.channelStatuses[mode] = data
            self.channelStatusSymbols[data[0]] = mode
            for index, status in enumerate(self.channelStatusOrder):
                if self.channelStatuses[status][1] < data[1]:
                    self.channelStatusOrder.insert(index, mode)
                    break
            else:
                self.channelStatusOrder.append(mode)
        for type, typeSet in enumerate(newUserModes):
            for mode, implementation in typeSet.iteritems():
                self.userModeTypes[mode] = type
                self.userModes[type][mode] = implementation
        for action, actionData in newActions.iteritems():
            if action not in self.actions:
                self.actions[action] = []
            for index, handlerData in enumerate(self.actions[action]):
                if handlerData[1] < actionData[1]:
                    self.actions[action].insert(index, actionData)
                    break
            else:
                self.actions[action].append(actionData)
        for command, data in newUserCommands:
            if command not in self.userCommands:
                self.userCommands[command] = [data]
            else:
                for index, cmd in enumerate(self.userCommands[command]):
                    if cmd[1] < data[1]:
                        self.userCommands[command].insert(index, data)
                        break
                else:
                    self.userCommands[command].append(data)
        for command, data in newServerCommands:
            if comand not in self.serverCommands:
                self.serverCommands[command] = [data]
            else:
                for index, cmd in enumerate(self.serverCommands[command]):
                    if cmd[1] < data[1]:
                        self.serverCommands[command].insert(index, data)
                        break
                else:
                    self.serverCommands[command].append(data)
    
    def unloadModule(self, moduleName, fullUnload = True):
        unloadDeferreds = []
        if moduleName not in self.loadedModules:
            return
        module = self.loadedModules[moduleName]
        moduleData = self._loadedModuleData[moduleName]
        d = module.unload()
        if d is not None:
            unloadDeferreds.append(d)
        
        for modeData in moduleData["channelmodes"]:
            if modeData[1] == ModeType.Status:
                del self.channelStatuses[modeData[0]]
                del self.channelStatusSymbols[modeData[4]]
                self.channelStatusOrder.remove(modeData[0])
            else:
                del self.channelModes[modeData[1]][modeData[0]]
            del self.channelModeTypes[modeData[0]]
        for modeData in moduleData["usermodes"]:
            del self.userModes[modeData[1]][modeData[0]]
            del self.userModeTypes[modeData[0]]
        for actionData in moduleData["actions"]:
            self.actions[actionData[0]].remove((actionData[2], actionData[1]))
        for commandData in moduleData["usercommands"]:
            self.userCommands[commandData[0]].remove((commandData[2], commandData[1]))
        for commandData in moduleData["servercommands"]:
            self.serverCommands[commandData[0]].remove((commandData[2], commandData[1]))
        
        if fullUnload:
            d = module.fullUnload()
            if d is not None:
                unloadDeferreds.append(d)
        del self.loadedModules[moduleName]
        del self._loadedModuleData[moduleName]
        if unloadDeferreds:
            return DeferredList(unloadDeferreds)
    
    def reloadModule(self, moduleName):
        d = self.unloadModule(moduleName, False)
        if d is None:
            self.loadModule(moduleName)
        else:
            d.addCallback(lambda result: self.loadModule(moduleName))
    
    def rehash(self):
        log.msg("Rehashing...", logLevel=logging.INFO)
        self.config.reload()
        d = self._unbindPorts() # Unbind the ports that are bound
        if d: # And then bind the new ones
            DeferredList(d).addCallback(lambda result: self._bindPorts())
        else:
            self._bindPorts()
        for module in self.loadedModules.itervalues(): # Tell modules about it
            module.rehash()
    
    def _bindPorts(self):
        for bindDesc in self.config["bind_client"]:
            try:
                endpoint = serverFromString(reactor, unescapeEndpointDescription(bindDesc))
            except ValueError as e:
                log.msg(str(e), logLevel=logging.ERROR)
                continue
            listenDeferred = endpoint.listen(UserFactory(self))
            listenDeferred.addCallback(self._savePort, bindDesc)
            listenDeferred.addErrback(self._logNotBound, bindDesc)
        for bindDesc in self.config["bind_server"]:
            try:
                endpoint = serverFromString(reactor, unescapeEndpointDescription(bindDesc))
            except ValueError as e:
                log.msg(str(e), logLevel=logging.ERROR)
                continue
            listenDeferred = endpoint.listen(ServerListenFactory(self))
            listenDeferred.addCallback(self._savePort, bindDesc)
            listenDeferred.addErrback(self._logNotBound, bindDesc)
    
    def _unbindPorts(self):
        deferreds = []
        for port in self.boundPorts.itervalues():
            d = port.stopListening()
            if d:
                deferreds.append(d)
        return deferreds
    
    def _savePort(self, port, desc):
        self.boundPorts[desc] = port
    
    def _logNotBound(self, err, desc):
        log.msg("Could not bind '{}': {}".format(desc, err), logLevel=logging.ERROR)

class ModuleLoadError(Exception):
    def __init__(self, name, desc):
        self.name = name
        self.desc = desc
    
    def __str__(self):
        return "Module {} could not be loaded: {}".format(name, desc)