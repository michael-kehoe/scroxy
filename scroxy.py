from pysnmp.carrier.asynsock.dgram import udp, udp6
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, cmdgen, context
from pysnmp.proto.api import v2c
from pysnmp import error
from pysnmp import debug
import sys
import redis
from ConfigParser import SafeConfigParser
from pprint import pprint

# community-name -> target-name, target-address
agentMap = {}
systems = {}

configfile = SafeConfigParser()
configfile.read("config.conf.php")
#snmp_manager = SnmpManager()
for system in [s for s in configfile.sections() if s.startswith('system')]:
  systems[system] = {  'id': configfile.get(system, 'id'),
                          'description': configfile.get(system, 'description'),
                          'address': configfile.get(system, 'address'),
                          'port': int(configfile.get(system, 'port')),
                          'device_community': configfile.get(system, 'device_community'),
                          'scroxy_community': configfile.get(system, 'scroxy_community'),
                          'version': configfile.get(system, 'version'),
                          'authUser': configfile.get(system, 'authuser'),
                      }
  agentMap[configfile.get(system, 'scroxy_community')] = (configfile.get(system, 'id'),configfile.get(system, 'address'))
  #print 'Added: ' + 'id:' + idno + ' description:' + descr + ' address:' + address + ' port:' + port + ' device_community:' + device_community + ' scroxy_community:' + scroxy_community + ' version:' + version
  
#Create SNMP engine
snmpEngine = engine.SnmpEngine()

# Bind Server to v4 port
config.addSocketTransport(
      snmpEngine,
      udp.domainName + (1,),
      udp.UdpTransport().openServerMode(('0.0.0.0', 1161))
)   

# Bind Server to v6 port 
config.addSocketTransport(
    snmpEngine,
    udp6.domainName,
    udp6.Udp6Transport().openServerMode(('::1', 1161))
)

#Add v4 client transport
config.addSocketTransport(
      snmpEngine,
      udp.domainName + (2,),
      udp.UdpTransport().openClientMode()
)

securityMappings = []

#Create backends
for coms in systems.values():
  config.addV1System(snmpEngine, coms['scroxy_community'], coms['scroxy_community'], contextName=coms['scroxy_community'])
  print "config.addV1System():" + coms['id'] + ' with context:' + coms['scroxy_community']
      
for coms in systems.values():
  test = coms['device_community'] + '-' + coms['version']
  if securityMappings.count(test)  < 1:
    securityMappings.append(test)
    if coms['version'] == '1' or coms['version'] == '2c':
      bename = 'bea-v12-' + coms['device_community']
      #securityname = 'beaa-' + coms['version'] + '-' + coms['device_community']
      config.addV1System(snmpEngine, bename, coms['device_community']) 
      print 'config.addV1System() ' + bename + ' community: ' + coms['device_community']

      if coms['version'] == '1':   
        securityname = 'beaa-' + coms['version'] + '-' + coms['device_community']
        config.addTargetParams(snmpEngine, securityname, bename,'noAuthNoPriv', 0)
        print 'Add Target Params::v1::' + securityname + '::' + bename
      else:
        securityname = 'beaa-' + coms['version'] + '-' + coms['device_community']
        config.addTargetParams(snmpEngine, securityname, bename,'noAuthNoPriv', 1)
        print 'Add Target Params::v2c::' + securityname + '::' + bename
    else:
      bename = 'backend-area-v3-' + coms['authUser']
      securityname = coms['version'] + '-' + coms['authUser'] + '-auth'  

#Add systems
for coms in systems.values():
  securityname = 'beaa-' + coms['version'] + '-' + coms['device_community']
  config.addTargetAddr(snmpEngine, coms['id'] ,udp.domainName + (2,), (coms['address'], coms['port']), securityname, retryCount=0)
  print 'config.addTargetAddr() id=' + coms['id'] + ' IP=' + coms['address'] + ' SN=' + securityname  

#Create redis client
r = redis.StrictRedis(host='perez.micko.dyndns.org', port=6379, db=0)

# Default SNMP context
config.addContext(snmpEngine, '')

class CommandResponder(cmdrsp.CommandResponderBase):
    cmdGenMap = { 
        v2c.GetRequestPDU.tagSet: cmdgen.GetCommandGenerator(),
        v2c.SetRequestPDU.tagSet: cmdgen.SetCommandGenerator(),
        v2c.GetNextRequestPDU.tagSet: cmdgen.NextCommandGeneratorSingleRun(),
        v2c.GetBulkRequestPDU.tagSet: cmdgen.BulkCommandGeneratorSingleRun() 
    }
    pduTypes = cmdGenMap.keys()  # This app will handle these PDUs

    # SNMP request relay
    def handleMgmtOperation(self, snmpEngine, stateReference, contextName,
                            PDU, acInfo):
        cbCtx = snmpEngine, stateReference
        varBinds = v2c.apiPDU.getVarBinds(PDU)
       
        try:
          if contextName not in agentMap:
            raise PySnmpError('Unknown context name %s' % contextName)

          # Select backend Agent ID by contextName arrived with request
          targetName, targetAddress = agentMap[contextName]
        
          indice = 0
          for oid in varBinds:
            k,v = oid
            key = targetAddress + "-" + str(oid[0])
            if r.exists(key) == True:
              v = r.get(key)
              varBinds[indice] = (k,v)
              self.sendRsp(snmpEngine, stateReference,  0, 0, varBinds)
            else:
              if PDU.tagSet == v2c.GetBulkRequestPDU.tagSet:
                self.cmdGenMap[PDU.tagSet].sendReq(
                    snmpEngine, targetName,
                    v2c.apiBulkPDU.getNonRepeaters(PDU),
                    v2c.apiBulkPDU.getMaxRepetitions(PDU),
                    varBinds,
                    self.handleResponse, cbCtx
                )
              elif PDU.tagSet in self.cmdGenMap:
                self.cmdGenMap[PDU.tagSet].sendReq(
                    snmpEngine, targetName, varBinds,
                    self.handleResponse, cbCtx
                )
            indice = indice + 1
        except error.PySnmpError:
          print sys.exc_info()[1]
          self.handleResponse(stateReference,  'error', 0, 0, varBinds, cbCtx)
    
    # SNMP response relay
    def handleResponse(self, sendRequestHandle, errorIndication, 
                       errorStatus, errorIndex, varBinds, cbCtx):
        if errorIndication:
            errorStatus = 5
            errorIndex = 0
            varBinds = ()

        snmpEngine, stateReference = cbCtx 
        hosts = snmpEngine.cache['getTargetAddr']['nameToTargetMap']
        host = ""
        for key in hosts.items():
          k,v = key
          host = v[1][0]
        for a in varBinds:
          key = str(host) + "-" + str(a[0])
          r.setex(key, 120, a[1])
        self.sendRsp(snmpEngine, stateReference,  errorStatus, errorIndex, varBinds)

CommandResponder(snmpEngine, context.SnmpContext(snmpEngine))
snmpEngine.transportDispatcher.jobStarted(1) # this job would never finish
# Run I/O dispatcher which would receive queries and send responses
snmpEngine.transportDispatcher.runDispatcher()



