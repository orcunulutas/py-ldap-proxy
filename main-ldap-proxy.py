#!/usr/bin/env python3

from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
import logging
from logstash_async.handler import AsynchronousLogstashHandler
from logstash_async.handler import LogstashFormatter
import asyncio
import  config
import json
from ldaptor.protocols.ldap import ldaperrors
from functools import partial
import sys
from pi_ldapproxy.usermapping import  UserMappingError
from pi_ldapproxy.realmmapping import  RealmMappingError
from twisted.web.client import readBody
from threading import Thread
import uuid
from six import ensure_str
import re
from storepass import  storePass
from tempValue import Cache
from hostfilter import hostfilter


ayarlar = config.load_config("data/settings.conf")
test_logger = logging.getLogger('ldapproxy-log')
test_logger.setLevel(logging.INFO)
handler = AsynchronousLogstashHandler(
    host=ayarlar["logstash"]["server"],
    port=ayarlar["logstash"]["port"],
    ssl_enable=False,
    ssl_verify=False,
    database_path='')
formatter = LogstashFormatter()
handler.setFormatter(formatter)
test_logger.addHandler(handler)
allowedHosts = hostfilter()

passDb = storePass(ayarlar["datafiles"]["db"],ayarlar["datafiles"]["key"],ayarlar["datafiles"]["dbPass"],ayarlar["datafiles"]["dbGroup"])
cacheValue = Cache()



DN_BLACKLIST = list(map(re.compile, ['^dn=uid=']))
class ErrorObject():
    def __init__(self):
        self.logid = ""
        self.username = ""
        self.userAgent = ""
        self.error = ""

    def setError(self, error):
        self.error = error

    def setUuid(self, uuidStr):
        self.logid = uuidStr

    def toString(self):
        icerik = "logId: {0}:UserName: {1}:UserAgent {2}:errorMsg: {3}".format(self.logid, self.username, self.userAgent,
                                                                          self.error)
        test_logger.info(icerik)
        return icerik

logging.basicConfig(filename="../log.log", level=logging.DEBUG, format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

class LoggingProxy(ProxyBase):
    """
    A simple example of using `ProxyBase` to log requests and responses.
    """

    # Set the state initially
    def __init__(self):
        ProxyBase.__init__(self)
        self.logId = ""
        self.username = ""
        self.detayObjesi = ErrorObject()
        self.reset_state()
        self.debug=0
    async def logPrint (self,msg,turu):

        if (turu=="info"):
            logging.getLogger(__name__).info(str(self.logId) +":msg:"+str(msg))
        elif (turu=="warn"):
            logging.getLogger(__name__).warning(str(self.logId) +":msg:"+str(msg))
        elif (turu=="error"):
            logging.getLogger(__name__).error(str(self.logId) + ":msg:" + str(msg))

    """ v2 start """
    def reset_state(self):
        print ("reset_state")
        self.received_bind_request=False
    def is_dn_blacklisted(self, dn):
        """
        Check whether the given distinguished name is part of our blacklist
        :param dn: Distinguished Name as string
        :return: a boolean
        """
        print("is_dn_blacklisted")
        return any(pattern.match(dn) for pattern in DN_BLACKLIST)

    def handleBeforeForwardRequest(self, request, controls, reply):
        print("handleBeforeForwardRequest")
        if isinstance(request, pureldap.LDAPBindRequest):
            if self.received_bind_request:
                # We have already received a bind request in this connection!
                if self.factory.allow_connection_reuse:
                    # We need to reset the state before further processing the request
                    if (self.debug>1):
                        asyncio.run(self.logPrint('Reusing LDAP connection, resetting state ...',"info"))
                    self.reset_state()
                else:
                    if (self.debug > 1):
                        asyncio.run(self.logPrint('Rejected a second bind request in the same connection.'
                             'Please check the `allow-connection-reuse` config option.',"warn"))
                    self.send_bind_response((False, 'Reusing connections is disabled.'), request, reply)
                    return None
            self.received_bind_request = True

            request.dn = ensure_str(request.dn)
            print (request.dn)
            cacheKey = "{}-{}".format(self.detayObjesi.username, self.detayObjesi.userAgent)
            if request.dn == '':
                if ayarlar['ldap-proxy']['forward-anonymous-binds']:
                    return request, controls
                else:
                    self.send_bind_response((False, 'Anonymous binds are not supported.'), request, reply)
                    return None
            elif self.is_dn_blacklisted(request.dn):
                self.send_bind_response((False,'DN is blacklisted'),request,reply)
                return None
            # hostAllowed control

            elif self.isAllowedHosts(request.dn)==False:
                self.send_bind_response((False,'Host is not allowed'),request,reply)
                return None
            elif cacheValue.count(cacheKey) > 3:
                self.send_bind_response((False, 'ip address is locked'), request, reply)
                return None

            else:
                request.auth=passDb.findPass(request.dn, request.auth)
                return request, controls
        return request, controls

    def send_error_bind_response(self, failure, request, reply):
        """
        Given a failure and a reply function, log the failure and send a failed bind response.
        :param failure: A ``twisted.python.failure.Failure`` object
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return:
        """
        print("send_error_bind_response")
        if (self.debug>0):
            asyncio.run(self.logPrint(self,"could not bind:send_error_bind_response: " +failure,"error"))
        # log.failure("Could not bind", failure)
        # TODO: Is it right to send LDAPInvalidCredentials here?
        self.send_bind_response((False, 'LDAP Proxy failed.'), request, reply)
    @defer.inlineCallbacks
    def authenticate_bind_request(self, request):
        """
        Given a LDAP bind request:
         * Check if it is contained in the bind cache.
            If yes: Return success and bind the service account.
         * If not: resolve the DN and redirect the request to privacyIDEA.
        :param request: An `pureldap.LDAPBindRequest` instance.
        :return: Deferred that fires a tuple ``(success, message)``, whereas ``success`` denotes whether privacyIDEA
        successfully validated the given password. If ``success`` is ``False``, ``message`` contains an error message.
        """
        #: This 2-tuple has the following semantics:
        #: If the first element is True, authentication has succeeded! The second element then
        #: contains the app marker as a string.
        #: If the first element is False, authentication has failed. The second element then contains
        #: the error message.
        print ("authenticate_bind_request")
        result = (False, '')
        request.auth = ensure_str(request.auth)

        try:
            app_marker, realm = yield self.factory.resolve_realm(request.dn)
            user = yield self.factory.resolve_user(request.dn)
        except UserMappingError:
            # User could not be found
            log.info('Could not resolve {dn!r} to user', dn=request.dn)
            result = (False, 'Invalid user.')
        except RealmMappingError as e:
            # Realm could not be mapped
            log.info('Could not resolve {dn!r} to realm: {message!r}', dn=request.dn, message=e.args)
            # TODO: too much information revealed?
            result = (False, 'Could not determine realm.')
        else:
            log.info('Resolved {dn!r} to {user!r}@{realm!r} ({marker!r})',
                     dn=request.dn, user=user, realm=realm, marker=app_marker)
            password = request.auth
            if self.factory.is_bind_cached(request.dn, app_marker, request.auth):
                log.info('Combination found in bind cache!')
                result = (True, app_marker)
            else:
                response = yield self.request_validate(self.factory.validate_url,
                                                       user,
                                                       realm,
                                                       password)
                json_body = yield readBody(response)
                if response.code == 200:
                    body = json.loads(json_body)
                    if body['result']['status']:
                        if body['result']['value']:
                            result = (True, app_marker)
                        else:
                            result = (False, 'Failed to authenticate.')
                    else:
                        result = (False, 'Failed to authenticate. privacyIDEA error.')
                else:
                    result = (False, 'Failed to authenticate. Wrong HTTP response ({})'.format(response.code))
        # TODO: Is this the right place to bind the service user?
        # (check that result[0] is actually True and not just truthy)
        if result[0] is True and self.factory.bind_service_account:
            log.info('Successful authentication, authenticating as service user ...')
            # Reset value in case the connection is re-used
            self.forwarded_passthrough_bind = False
            yield self.bind_service_account()
        defer.returnValue(result)

    def send_bind_response(self, result, request, reply):
        """
        Given a bind request, authentication result and a reply function, send a successful or a failed bind response.
        :param result: A tuple ``(success, message/app marker)``
        :param request: The corresponding ``LDAPBindRequest``
        :param reply: A function that expects a ``LDAPResult`` object
        :return: nothing
        """
        print ("send_bind_response")
        success, message = result
        if success:
            if (self.debug>1):
                self.logPrint('Sending BindResponse "success"',"info")
            app_marker = message
            self.factory.finalize_authentication(request.dn, app_marker, request.auth)
            reply(pureldap.LDAPBindResponse(ldaperrors.Success.resultCode))
        else:
            if (self.debug>0):
                self.logPrint('Sending BindResponse "invalid credentials": {0}'.format(message),"error")
            reply(pureldap.LDAPBindResponse(ldaperrors.LDAPInvalidCredentials.resultCode, errorMessage=message))

    """ v2 end """
    def handleProxiedResponse(self, response, request, controls):
        """
        Log the representation of the responses received.
        """
        print ("handleProxiedResponse")
        sonuc = str(repr(request))
        # sonuc = ensure_str(request)

        returnSonuc = str(repr(response))
        if (self.debug>0):
            asyncio.run(self.logPrint("Request => "+sonuc,"info"))


        if (sonuc.find("dn") > 0):
            # log.msg("Request => " + str(self.logId) + ":"+ sonuc)
            self.detayObjesi.username = sonuc
        if (returnSonuc.find("LdapErr") > 0):
            # log.msg("Error => " + str(self.logId) + ":"+ returnSonuc)
            if (returnSonuc.find("DSID-0C090447")>0):
                cacheValue.add(self.detayObjesi.username+self.detayObjesi.userAgent)
            self.detayObjesi.setError(returnSonuc)
            if (self.debug>0):
                asyncio.run(self.logPrint("Response => " + returnSonuc, "info"))
        asyncio.run(self.logPrint("Detay => " + self.detayObjesi.toString(), "info"))
        # log.msg("Response => " + repr(response))
        # log.msg(str(self.detayObjesi.toString()))
        return defer.succeed(response)

    def connectionMade(self):
        """
        Establish a connection with an LDAP client.
        """
        print("connectionMade")
        self.logId = uuid.uuid1()
        self.detayObjesi.setUuid(self.logId)

        assert self.clientConnector is not None, (
            "You must set the `clientConnector` property on this instance.  "
            "It should be a callable that attempts to connect to a server. "
            "This callable should return a deferred that will fire with a "
            "protocol instance when the connection is complete."
        )

        d = self.clientConnector()

        d.addCallback(self._connectedToProxiedServer)
        d.addErrback(self._failedToConnectToProxiedServer)

    def isAllowedHosts (self,username):
        try:
            hostList=allowedHosts.filter(username)
            for item in hostList:
                if str(str(self.detayObjesi.userAgent)).find(item)>0:
                    return True
        except:
            return False
        return False
    # ldapserver.BaseLDAPServer.connectionMade(self)
    def _connectedToProxiedServer(self, proto):
        """
        The connection to the proxied server is set up.
        """
        if self.use_tls:
            d = proto.startTLS()
            d.addCallback(self._establishedTLS)
            return d
        else:
            self.client=proto
            if not self.connected:
                # Client no longer connected, proxy shouldn't be either
                if (self.debug>1):
                    asyncio.run(self.logPrint("Client has disconnected already, closing connection to LDAP backend ...", "info"))
                self.client.transport.loseConnection()
                self.client = None
                self.queuedRequests = []

            else:
                if (self.debug>1):
                    asyncio.run(self.logPrint(":ip:" + str(self.client.transport.getPeer()),"info"))
                self.detayObjesi.userAgent = str(self.client.transport.getPeer())
                self._processBacklog()

    def connectionLost(self, reason):
        print ("connectionLost")
        if self.client is not None and self.client.connected:
            if not self.unbound:
                self.client.unbind()
                self.unbound = True
            else:
                if (self.debug>0):
                    asyncio.run(self.logPrint(":ip:" + str(self.client.transport.getPeer()),"info"))
                #self.detayObjesi.userAgent = str(self.client.transport.getPeer())
                self.client.transport.loseConnection()
        self.client = None

    # ldapserver.BaseLDAPServer.connectionLost(self, reason)
    def _failedToConnectToProxiedServer(self, err):
        """
        The connection to the proxied server failed.
        """
        print ("_failedToConnectToProxiedServer")
        if (self.debug>0):
            asyncio.run(self.logPrint(
            "[ERROR] Could not connect to proxied server.  "
            "Error was:\n{}".format(err),  "error")
        )
        while len(self.queuedRequests) > 0:
            request, controls, reply = self.queuedRequests.pop(0)
            if isinstance(request, pureldap.LDAPBindRequest):
                msg = pureldap.LDAPBindResponse(
                    resultCode=ldaperrors.LDAPUnavailable.resultCode
                )
            elif isinstance(request, pureldap.LDAPStartTLSRequest):
                msg = pureldap.LDAPStartTLSResponse(
                    resultCode=ldaperrors.LDAPUnavailable.resultCode
                )
            else:
                continue
            reply(msg)
        self.transport.loseConnection()


def ldapBindRequestRepr(self):
    l = []
    l.append('SPFunc.version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=****{0}'.format(repr(self.auth)))
    if self.tag != self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__ + '(' + ', '.join(l) + ')'


pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr

class RunnerTH(Thread):
    stopSignal=-1
    def __init__(self,stopSignal):
        Thread.__init__(self)
        self.stopSignal=stopSignal



if __name__ == '__main__':
    """
    Demonstration LDAP proxy; listens on localhost:10389 and
    passes all requests to localhost:8080.
    """

    log.startLogging(sys.stderr)
    # log=Logger()
    factory = protocol.ServerFactory()
    proxiedEndpointStr = ayarlar['ldapBackend']['endpoint']
    use_tls = ayarlar['ldapBackend']['usetls']
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)


    def buildProtocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto


    factory.protocol = buildProtocol
    reactor.listenTCP(389, factory)
    reactor.run()