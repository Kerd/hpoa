#!/bin/env python
# Copyright (c) 2021 Kirill Kuteynikov
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

r"""
This module implements API for HP Insight Onboard Administrator SOAP Interface.
It was made to gather information and manage HP BladeSystem c7000 Enclosures.

Usage example is provided a the end of this file.

:copyright: (c) 2021 by Kirill Kuteynikov
:license: Apache2, see LICENSE for more details.
"""

import sys
import socket
import warnings
import requests
import lxml
import logging
from lxml.builder import ElementMaker
from lxml import etree
from requests.adapters import HTTPAdapter

__version__ = '1.0'

SOAP_API_NAME = 'HP Insight Onboard Administrator SOAP Interface'

UNKNOWN_ERROR = 1
USERNAME_OR_PASSWORD_INCORRECT = 150
OA_COUNT = 2
BLADES_COUNT = 16
INTERCONNECT_COUNT = 8
PSU_COUNT = 6
FAN_COUNT = 10

LOG = logging.getLogger('HPOA')

warnings.filterwarnings("ignore", message='.*Upgrade your password.*', category=UserWarning)

tcp_timeout = 5
ns = {'SOAP-ENV': 'http://www.w3.org/2003/05/soap-envelope',
      'wsse': 'http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd',
      'hpoa': 'hpoa.xsd'}
S = ElementMaker(namespace="http://www.w3.org/2003/05/soap-envelope", nsmap=ns)
H = ElementMaker(namespace="hpoa.xsd", nsmap=ns)
W = ElementMaker(namespace="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd", nsmap=ns)

class HostNameIgnoringAdapter(HTTPAdapter):
    def cert_verify(self, conn, url, verify, cert):
        conn.assert_hostname = False
        return super(HostNameIgnoringAdapter, self).cert_verify(
            conn, url, verify, cert)

class APIException(Exception):
    def __init__(self, msg, reason=None):
        self.reason = reason
        super(APIException, self).__init__(msg)
    def log_error(self):
        return _log_error(self.reason)

class ParameterException(Exception):
    pass

def _error_code(result):
    #r = result.find('SOAP-ENV:Fault', ns)
    flt = result.find('Fault', ns)
    if flt is None:
        return 0
    errCode = flt.find('Detail/faultInfo/errorCode')
    if errCode is not None:
        return int(errCode.text)
    # Parse error response here
    return UNKNOWN_ERROR 

def _log_error(result):
    if result.tag == 'Body':
        body = result
    elif result.tag == 'Envelope':
        body = result.find('Body')
    else:
        LOG.error("HPOA API error: can't find response body.")
        return True
        
    flt = body.find('Fault', ns)

    if flt is None:
        return False
    
    msg = _error_text(body)

    for txt in msg:
        LOG.error('HPOA API error: %s', txt)

    return True

def _error_text(body):
    msg = []
    flt = body.find('Fault', ns)
    if flt is None:
        return []

    nfo = flt.find('faultstring')
    if nfo is not None:
        msg.append(nfo.text)

    nfo = flt.find('Reason/Text')
    if nfo is not None:
        msg.append(nfo.text)

    nfo = flt.find('Detail/faultInfo')
    if nfo is not None:
        op = nfo.find('operationName')
        txt = nfo.find('errorText')
        msg.append('%s: %s' % ('?' if op is None else op.text,
                'N/A' if txt is None else txt.text))
    return msg

def _remove_ns(xml):
    # Remove namespace prefixes
    for el in xml.getiterator():
        el.tag = etree.QName(el).localname
        for a, v in el.items():
            q = etree.QName(a)
            if q is not None:
                del el.attrib[a]
                el.attrib[q.localname] = v
    # Remove unused namespace declarations
    etree.cleanup_namespaces(xml)
    return xml

class HPOA:

    def __init__(self, addresses, username=None, password=None,
                    ssl_verify=None,
                    cert_path=None,
                    api_validate=True,
                    timeout=5.0):
        self.addresses = addresses if isinstance(addresses, list) else [addresses]
        self.username = username
        self.password = password
        self.ssl_verify = ssl_verify
        self.cert_path = cert_path
        self.api_validate = api_validate
        self.encoding = "utf-8"
        self.timeout = timeout
        self.session_hdr = None

        if not self.ssl_verify and hasattr(requests, 'packages'):
            LOG.warning("Suppressing requests library SSL Warnings")
            requests.packages.urllib3.disable_warnings(
                requests.packages.urllib3.exceptions.InsecureRequestWarning)
           # requests.packages.urllib3.disable_warnings(
           #     requests.packages.urllib3.exceptions.InsecurePlatformWarning)
        
    def _set_session_hdr(self, session_key):
        sec = W.Security(H.HpOaSessionKeyToken(H.oaSessionKey(session_key)))
        sec.attrib['{%s}mustUnderstand' % ns["SOAP-ENV"]] = "true"
        self.session_hdr = S.Header(sec)

    def _soap_req(self, data):
        if self.session_hdr is not None:
            return S.Envelope(self.session_hdr, S.Body(data))
        return S.Envelope(S.Body(data))

    def _parse_response(self, r):
        ctype = r.headers["content-type"]
        if 'application/soap+xml' in ctype:
            try:
                result = _remove_ns(etree.fromstring(r.content))
                #body = result.find('SOAP-ENV:Body', ns)
                body = result.find('Body', ns)
                if body is not None:
                    if _log_error(body):
                        msg = _error_text(body)
                        raise APIException(msg, reason = body)
                    return body
                msg = "Invalid XML response from OA API. Can't find Body element."
                raise APIException(msg, reason = result) 
            except lxml.etree.XMLSyntaxError as e:
                msg = "XML parser failed to parse HPOA API response: %s" % e
            except APIException:
                raise
            except Exception as e:
                LOG.exception(e)
                msg = "Error while parsing HPOA API XML response: %s" % e
            raise APIException(msg)
        elif 'text/plain' in ctype:
            raise APIException('Invalid HPAO API response content: %s' % r.text)
        elif 'text/html' in ctype:
            raise APIException('HTML response received. Probably invalid HPOA API address provided.')
        else:
            raise APIException('Unsupported HPOA API response Content-Type: %s' % ctype)

    def send_request(self, data):
        req = etree.tostring(self._soap_req(data))

        if LOG.isEnabledFor(logging.DEBUG):
           LOG.debug("Request: %s", req)
            
        r = self._session.post(self.url, data=req, timeout=self.timeout)
        
        if LOG.isEnabledFor(logging.DEBUG - 5):
            LOG.debug("Raw response: %s", r.text)

        body = self._parse_response(r)

        if r.status_code != 200:
            raise APIException('HPAO API response code is not OK: %d' % r.status_code, reason=body)

        if LOG.isEnabledFor(logging.DEBUG):
            LOG.debug("Response: %s", etree.tostring(body, pretty_print=True).decode('utf-8'))

        return body

    def _try_login(self):
        if self.username is None or self.username == '':
            body = self.getSoapInterfaceInfo()
            if self.api_validate:
                name = body.find('getSoapInterfaceInfoResponse/soapInterfaceInfo/name')
                if name is None or name.text != SOAP_API_NAME:
                    LOG.info("HPOA API interface is not available at %s", self.url)
                    return False
            return True
        body = self.userLogIn(self.username, self.password)
        #key = body.find('hpoa:userLogInResponse/hpoa:HpOaSessionKeyToken/hpoa:oaSessionKey', ns)
        key = body.find('userLogInResponse/HpOaSessionKeyToken/oaSessionKey')
        if key is None:
            LOG.error("Can't get session key: %s", etree.tostring(body, pretty_print=True).decode('utf-8'))
            raise APIException("Session key not found in OA API response", reason = body)
        self._set_session_hdr(key.text)
        return True
        
    def login(self):
        self._session = requests.Session()
        self._session.headers.update({
            "Connection": "keep-alive",
            "Content-Type": "text/plain; charset=utf-8"})
        self._session.verify = False
        if self.ssl_verify:
            self._session.verify = self.cert_path

        for addr in self.addresses:
            self.url = 'https://%s/hpoa' % addr.lower()
            LOG.info("Connecting to " + self.url)
            try:
                self._session.mount(self.url, HostNameIgnoringAdapter())
                if not self._try_login():
                    continue
            except requests.exceptions.ConnectionError as e:
                LOG.warning('Failed to connect to OA[%s]: %s', self.url, e)
            except APIException as e:
                if _error_code(e.reason) == USERNAME_OR_PASSWORD_INCORRECT:
                    LOG.error("HPOA API can't authorize: Invalid username or password provided.")
                    break
                LOG.exception('API exception: %s', e)
            except Exception as e:
                LOG.exception('Failed to login server %s: %s', self.url, e)
                raise
            else:
                # Sort the login url to the last slot of san addresses, so that
                # if this connection error, next time will try other url first.
                self.addresses.remove(addr)
                self.addresses.append(addr)
                LOG.info('Login %s success.', addr)
                return

        self._session.close()
        self._session = None

        raise APIException("Failed to login to OA.")

    def logout(self):
        if self.session_hdr is None:
            return
        try:
            self.userLogOut()
            self.session_hdr = None
        except Exception:
            self.session_hdr = None

    def close(self):
        if self.tran:
            self.tran.close()
            self.tran = None

    def get_enclosure_info(self):
        data = self.getEnclosureInfo()
        return data

    def get_enclosure_status(self):
        data = self.getEnclosureStatus()
        return data

    def get_enclosure_network_info(self):
        data = self.getEnclosureNetworkInfo()
        return data

    def get_oa_info(self, rng = None):
        rng = rng if rng is not None else range(1, OA_COUNT + 1)
        data = self.getOaInfoArray(rng)
        return data

    def get_oa_status(self, rng = None):
        rng = rng if rng is not None else range(1, OA_COUNT + 1)
        data = self.getOaStatusArray(rng)
        return data

    def get_oa_network_info(self, rng = None):
        rng = rng if rng is not None else range(1, OA_COUNT + 1)
        data = self.getOaNetworkInfo(rng)
        return data

    def get_blade_info(self, rng = None):
        rng = rng if rng is not None else range(1, BLADES_COUNT + 1)
        data = self.getBladeInfoArray(rng)
        return data

    def get_blade_status(self, rng = None):
        rng = rng if rng is not None else range(1, BLADES_COUNT + 1)
        data = self.getBladeStatusArray(rng)
        return data

    def get_psu_info(self, rng = None):
        rng = rng if rng is not None else range(1, PSU_COUNT + 1)
        data = self.getPowerSupplyInfoArray(rng)
        return data

    def get_blade_mp_info(self, bay):
        data = self.getBladeMpInfo(bay)
        return data

    def get_psu_status(self, rng = None):
        rng = rng if rng is not None else range(1, PSU_COUNT + 1)
        data = self.getPowerSupplyStatusArray(rng)
        return data

    def get_interconnect_info(self, rng = None):
        rng = rng if rng is not None else range(1, INTERCONNECT_COUNT + 1)
        data = self.getInterconnectTrayInfoArray(rng)
        return data

    def get_interconnect_status(self, rng = None):
        rng = rng if rng is not None else range(1, INTERCONNECT_COUNT + 1)
        data = self.getInterconnectTrayStatusArray(rng)
        return data

    def get_fan_info(self, rng = None):
        rng = rng if rng is not None else range(1, FAN_COUNT + 1)
        data = self.getFanInfoArray(rng)
        return data

    def get_lcd_info(self):
        data = self.getLcdInfo()
        return data

    def get_lcd_status(self):
        data = self.getLcdStatus()
        return data

    def get_power_subsystem_info(self):
        data = self.getPowerSubsystemInfo()
        return data

    def get_thermal_subsystem_info(self):
        data = self.getThermalSubsystemInfo()
        return data

    def get_users(self):
        data = self.getUsers()
        return data

    def get_ldap_groups(self):
        data = self.getLdapGroups()
        return data

    def get_ers_config_info(self):
        data = self.getErsConfigInfo()
        return data

methods = {
 'addBladeMpUser': ['bayNumber:int', 'username:string', 'fullname:string', 'password:string', 'adminPriv:boolean', 'remoteConsPriv:boolean', 'resetServerPriv:boolean', 'virtMediaPriv:boolean', 'configiLoPriv:boolean'],
 'addCaCertificate': ['certificate:string'],
 'addEbipaDnsServer': ['ebipaDevice:string', 'ipAddress:string'],
 'addEbipaNtpServer': ['ebipaDevice:string', 'ipAddress:string'],
 'addErsCertificate': ['certificate:string'],
 'addHpSimCertificate': ['hpSimCertificate:string'],
 'addHpSimXeName': ['xeName:string'],
 'addLanguagePack': ['langFilePath:string'],
 'addLdapDirectoryServerCertificate': ['ldapDirectoryServerCertificate:string'],
 'addLdapGroup': ['ldapGroup:string'],
 'addLdapGroupBayAccess': ['ldapGroup:string', 'bays:enclosureBaysSelection'],
 'addSnmpTrapReceiver': ['ipAddress:string', 'community:string'],
 'addSnmpTrapReceiver3': ['ipAddress:string', 'user:string', 'engineid:string', 'security:string', 'inform:boolean'],
 'addSnmpUser': ['username:string', 'authAlgorithm:string', 'authPassword:string', 'privAlgorithm:string', 'privPassword:string', 'engineid:string', 'security:string', 'rw:boolean'],
 'addTrustedIpAddress': ['ipAddress:string'],
 'addUser': ['username:string', 'password:string'],
 'addUserBayAccess': ['username:string', 'bays:enclosureBaysSelection'],
 'addVlan': ['vlanId:int', 'vlanName:string'],
 'askLcdCustomQuestion': ['screenName:string', 'questionText:string', 'questionButtonFormat:string', 'customAnswerMaxLen:byte'],
 'askLcdSimpleQuestion': ['screenName:string', 'questionText:string', 'questionType:string'],
 'bladeCrashNmi': ['bayNumber:int'],
 'bladeManualDiscovery': ['baySelection:enclosureBaysSelection'],
 'bladeManualUpdate': ['baySelection:enclosureBaysSelection'],
 'clearBladeSignature': ['bayNumber:int'],
 'clearErsServiceEvents': [],
 'clearFirmwareManagementAllLogs': [],
 'clearFirmwareManagementLog': [],
 'clearOaSyslog': ['bayNumber:int'],
 'clearOaVcmMode': [],
 'clearSshKeys': [],
 'configureEbipa': ['ebipaDevice:string', 'config:ebipaConfig'],
 'configureEbipaDev': ['ebipaInfo:ebipaDevInfo'],
 'configureEbipaEx': ['ebipaDevice:string', 'config:ebipaConfig'],
 'configureNtp': ['ntpPrimary:string', 'ntpSecondary:string', 'ntpPoll:int'],
 'configureOaDhcp': ['bayNumber:int', 'dynDns:boolean'],
 'configureOaIpv6DyndnsBay': ['bayNumber:int', 'dynDns:boolean'],
 'configureOaNicAuto': ['bayNumber:int'],
 'configureOaNicForced': ['bayNumber:int', 'speed:string', 'duplex:string'],
 'configureOaStatic': ['bayNumber:int', 'ipAddress:string', 'netmask:string'],
 'createCertificateRequest': [],
 'createSelfSignedCertificate': [],
 'disableErs': [],
 'disableUser': ['username:string'],
 'downloadCaCertificate': ['url:string'],
 'downloadCertificate': ['url:string'],
 'downloadCertificateEx': ['bayNumber:int', 'url:string'],
 'downloadConfigScript': ['url:string'],
 'downloadErsCertificate': ['url:string'],
 'downloadFile': ['fileType:string', 'fileUrl:string'],
 'downloadHpSimCertificate': ['url:string'],
 'downloadLdapDirectoryServerCertificate': ['url:string'],
 'downloadSshKeysFile': ['url:string'],
 'downloadUserCertificate': ['username:string', 'url:string'],
 'downloadVariable': ['variableKey:string', 'variableUrl:string'],
 'editVlan': ['vlanId:int', 'vlanName:string'],
 'ejectVirtualMedia': ['bayNumber:int', 'virtualMediaDeviceType:string'],
 'enableErs': ['mode:string', 'user:string', 'passwd:string', 'irsHostname:string', 'irsPort:int', 'optin:boolean', 'locale:string', 'iHaveReadAndAgreetoEndUserLicenseAgreement:boolean'],
 'enableLdapAuthentication': ['enableLdap:boolean', 'enableLocalUsers:boolean'],
 'enableTwoFactorAuthentication': ['enableTwoFactor:boolean', 'enableCrl:boolean', 'subjectAltName:boolean'],
 'enableUser': ['username:string'],
 'flashOaRom': ['oaFileToken:string', 'oaReset:boolean'],
 'flashOaRomEnhanced': ['oaFileToken:string', 'oaReset:boolean', 'forceFlash:boolean'],
 'flashOaRomFirmwareISO': ['forceFlash:boolean'],
 'generateCsr': ['bayNumber:int', 'certificateData:x509CertificateData'],
 'generateCsrEx': ['bayNumber:int', 'certificateDataEx:x509CertificateDataEx'],
 'generateHeartbeat': ['pid:int'],
 'generateOaConfigUsb': ['fileName:string'],
 'generateSelfSignedCertificate': ['bayNumber:int', 'certificateData:x509CertificateData'],
 'generateSelfSignedCertificateEx': ['bayNumber:int', 'certificateDataEx:x509CertificateDataEx'],
 'getAlertmailInfo': [],
 'getAllEvents': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean'],
 'getAllEventsEx': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean', 'oaFwVersion:string'],
 'getAllEventsWithoutPayload': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean'],
 'getAllEventsWithoutPayloadEx': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean', 'oaFwVersion:string'],
 'getBladeBootInfo': ['bayNumber:int'],
 'getBladeBootInfoEx': ['bayNumber:int'],
 'getBladeCNAInfo': ['bayNumber:int'],
 'getBladeClpStatus': ['bayNumber:int'],
 'getBladeClpStrings': ['bayNumber:int', 'mezz:int'],
 'getBladeCpuInfoExArray': ['bayNumber:int'],
 'getBladeDimmInfoArray': ['bayNumber:int'],
 'getBladeEfiStateInfo': ['bayNumber:int'],
 'getBladeFirmware': ['bayNumber:int'],
 'getBladeFirmwareArray': ['bayArray:bayArray'],
 'getBladeFirmwareExecLog': ['bayNumber:int'],
 'getBladeFirmwareHPSUMLog': ['bayNumber:int'],
 'getBladeFirmwareLog': ['bayNumber:int'],
 'getBladeInfo': ['bayNumber:int'],
 'getBladeInfoArray': ['bayArray:bayArray'],
 'getBladeMezzDevInfoEx': ['bayNumber:int'],
 'getBladeMezzDevInfoExArray': ['bayArray:bayArray'],
 'getBladeMezzFruSize': ['bayNumber:int'],
 'getBladeMezzInfoEx': ['bayNumber:int'],
 'getBladeMezzInfoExArray': ['bayArray:bayArray'],
 'getBladeMpCredentials': ['bayNumber:int'],
 'getBladeMpEv': ['bayNumber:int', 'evName:string'],
 'getBladeMpEventLog': ['bayNumber:int', 'maxsize:int'],
 'getBladeMpIml': ['bayNumber:int', 'maxsize:int'],
 'getBladeMpInfo': ['bayNumber:int'],
 'getBladePortMap': ['bayNumber:int'],
 'getBladePortMapArray': ['bayArray:bayArray'],
 'getBladePortMapWithClpInfo': ['bayNumber:int'],
 'getBladePortMapWithClpInfoArray': ['bayArray:bayArray'],
 'getBladePostLog': ['bayNumber:int'],
 'getBladePowerEfficiencyMode': ['bayNumber:int'],
 'getBladeSignatures': ['bayNumber:int'],
 'getBladeStatus': ['bayNumber:int'],
 'getBladeStatusArray': ['bayArray:bayArray'],
 'getBladeThermalInfoArray': ['bayNumber:int'],
 'getCaCertificatesInfo': [],
 'getConfigScript': [],
 'getCurrentAccessLevel': [],
 'getCurrentUserInfo': [],
 'getDeviceFru': ['device:string', 'bayNumber:int', 'address:int', 'offset:int', 'length:int'],
 'getDomainInfo': [],
 'getEbipaAddressList': ['beginAddress:string', 'netmask:string', 'bayArray:bayArray'],
 'getEbipaDevInfo': [],
 'getEbipaInfo': [],
 'getEbipaInfoEx': [],
 'getEbipav6AddressList': ['beginAddress:string', 'bayArray:bayArray'],
 'getEbipav6Info': [],
 'getEbipav6InfoEx': [],
 'getEncLink2': [],
 'getEnclosureBladePowerSummary': [],
 'getEnclosureInfo': [],
 'getEnclosureNetworkInfo': [],
 'getEnclosurePowerCollectionInfo': [],
 'getEnclosurePowerData': [],
 'getEnclosurePowerRecords': [],
 'getEnclosurePowerSummary': [],
 'getEnclosureStatus': [],
 'getEnclosureTime': [],
 'getErsCertificatesInfo': [],
 'getErsConfigInfo': [],
 'getEvent': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean'],
 'getEventEx': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean', 'oaFwVersion:string'],
 'getEventWithoutPayload': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean'],
 'getEventWithoutPayloadEx': ['pid:int', 'waitTilEventHappens:boolean', 'lcdEvents:boolean', 'oaFwVersion:string'],
 'getFanInfo': ['bayNumber:int'],
 'getFanInfoArray': ['bayArray:bayArray'],
 'getFanZoneArray': ['bayArray:bayArray'],
 'getFirmwareManagementLog': [],
 'getFirmwareManagementSettings': [],
 'getHpSimInfo': [],
 'getInterconnectTrayInfo': ['bayNumber:int'],
 'getInterconnectTrayInfoArray': ['bayArray:bayArray'],
 'getInterconnectTrayPortMap': ['bayNumber:int'],
 'getInterconnectTrayPortMapArray': ['bayArray:bayArray'],
 'getInterconnectTrayStatus': ['bayNumber:int'],
 'getInterconnectTrayStatusArray': ['bayArray:bayArray'],
 'getInterconnectTrayVcmInfoArray': [],
 'getInterconnectTrayVendorInfoBlock': ['bayNumber:int', 'blockNumber:int', 'numberOfBytes:int'],
 'getKvmInfo': [],
 'getLanguages': [],
 'getLcdInfo': [],
 'getLcdStatus': [],
 'getLcdUserNotes': [],
 'getLdapGroupInfo': ['ldapGroup:string'],
 'getLdapGroups': [],
 'getLdapInfo': [],
 'getLdapTestStatus': [],
 'getLoginBannerSettings': [],
 'getOaDbglog': ['bayNumber:int', 'maxsize:int'],
 'getOaId': [],
 'getOaInfo': ['bayNumber:int'],
 'getOaInfoArray': ['bayArray:bayArray'],
 'getOaMediaDeviceArray': ['bayNumber:int'],
 'getOaNetworkInfo': ['bayNumber:int'],
 'getOaSessionArray': ['bay:int'],
 'getOaSessionTimeout': [],
 'getOaStatus': ['bayNumber:int'],
 'getOaStatusArray': ['bayArray:bayArray'],
 'getOaSysInfo': ['bayNumber:int'],
 'getOaSyslog': ['bayNumber:int', 'maxsize:int'],
 'getOaSyslogExtended': ['bayNumber:int'],
 'getOaUpTime': ['bayNumber:int'],
 'getOaVcmMode': [],
 'getPasswordSettings': [],
 'getPowerCapBladeStatus': [],
 'getPowerCapConfig': [],
 'getPowerCapExtConfig': [],
 'getPowerConfigInfo': [],
 'getPowerReductionStatus': [],
 'getPowerSubsystemInfo': [],
 'getPowerSupplyInfo': ['bayNumber:int'],
 'getPowerSupplyInfoArray': ['bayArray:bayArray'],
 'getPowerSupplyStatus': ['bayNumber:int'],
 'getPowerSupplyStatusArray': ['bayArray:bayArray'],
 'getPowerdelaySettings': [],
 'getRackName': [],
 'getRackTopology': [],
 'getRackTopology2': [],
 'getSaPCIList': [],
 'getSnmpInfo': [],
 'getSnmpInfo3': [],
 'getSoapInterfaceInfo': [],
 'getSolutionsId': [],
 'getSshFingerprint': [],
 'getSshKeys': [],
 'getSslCertificateInfo': [],
 'getSslCertificateInfoEx': ['bayNumber:int'],
 'getSslSettings': [],
 'getSyslogSettings': [],
 'getThermalInfo': ['sensorType:string', 'bayNumber:int'],
 'getThermalSubsystemInfo': [],
 'getTimeZones': [],
 'getTwoFactorAuthenticationConf': [],
 'getUsbMediaConfigScripts': [],
 'getUsbMediaFirmwareImages': [],
 'getUserCertificateInfo': ['username:string'],
 'getUserInfo': ['username:string'],
 'getUsers': [],
 'getVariable': ['variableKey:string'],
 'getVariableList': [],
 'getVcmIpv6UrlList': [],
 'getVcmOaMinFwVersion': [],
 'getVirtualMediaStatus': ['bayNumber:int', 'virtualMediaDeviceType:string'],
 'getVirtualMediaUrlList': ['virtualMediaDeviceType:string'],
 'getVlanInfo': [],
 'hpqSetEnclosurePduType': ['enclosurePduType:int'],
 'hpqUpdateDevice': ['cmd:string'],
 'insertVirtualMedia': ['bayNumber:int', 'virtualMediaDeviceType:string', 'virtualMediaUrl:string'],
 'isMaxLdapGroupsReached': [],
 'isMaxUsersReached': [],
 'isOaAccess': [],
 'isValidNtpServer': ['ipAddress:string'],
 'isValidSession': [],
 'ldapGroupExists': ['ldapGroup:string'],
 'oaManualFailover': [],
 'pingUrl': ['url:string', 'count:int', 'pingUrlResultMaxSize:int'],
 'pressLcdButton': ['lcdButton:string', 'lcdButtonState:string'],
 'removeBladeMpCredentials': ['bayNumber:int', 'mpCredentials:bladeMpCredentials'],
 'removeCaCertificate': ['fingerprint:string'],
 'removeEbipaDnsServer': ['ebipaDevice:string', 'ipAddress:string'],
 'removeEbipaNtpServer': ['ebipaDevice:string', 'ipAddress:string'],
 'removeErsCertificate': ['fingerprint:string'],
 'removeHpSimCertificate': ['subjectCommonName:string'],
 'removeHpSimXeName': ['xeName:string'],
 'removeLanguagePack': ['langCode:string'],
 'removeLdapDirectoryServerCertificate': ['ldapDirectoryServerCertificateMd5Fingerprint:string'],
 'removeLdapGroup': ['ldapGroup:string'],
 'removeLdapGroupBayAccess': ['ldapGroup:string', 'bays:enclosureBaysSelection'],
 'removeOaSession': ['bay:int', 'session:string'],
 'removeOaSessionsAndProcesses': ['uidStart:int', 'uidEnd:int', 'lgroupStart:int', 'lgroupEnd:int', 'ipAllow:ipAddressArray'],
 'removeSnmpTrapReceiver': ['ipAddress:string'],
 'removeSnmpTrapReceiver3': ['ipAddress:string', 'user:string', 'engineid:string'],
 'removeSnmpTrapReceiverEx': ['ipAddress:string', 'community:string'],
 'removeSnmpUser': ['username:string', 'engineid:string'],
 'removeTrustedIpAddress': ['ipAddress:string'],
 'removeUser': ['username:string'],
 'removeUserBayAccess': ['username:string', 'bays:enclosureBaysSelection'],
 'removeUserCertificate': ['username:string'],
 'removeVlan': ['vlanId:int'],
 'requestFirmwareImage': ['oa:int'],
 'resetInterconnectTray': ['bayNumber:int'],
 'resetLcdUserNotes': [],
 'resetLcdUserNotesImage': [],
 'resetOa': ['bayNumber:int', 'delay:int'],
 'restoreFactoryDefaults': [],
 'revertVlan': ['delay:int'],
 'saveConfig': [],
 'sendErsDataCollection': [],
 'sendLcdMessage': ['screenName:string', 'message:string'],
 'setAlertmailDomain': ['emailDomain:string'],
 'setAlertmailReceiver': ['emailAddress:string'],
 'setAlertmailSenderEmail': ['emailAddress:string'],
 'setAlertmailSenderName': ['senderName:string'],
 'setAlertmailServer': ['ipAddress:string'],
 'setBladeEfiStateInfo': ['bayNumber:int', 'blockData:base64Binary'],
 'setBladeEfiStateInfoRxEnd': ['bayNumber:int', 'uniqueId:unsignedInt'],
 'setBladeIplBootPriority': ['bayNumber:int', 'bladeIplArray:bladeIplArray'],
 'setBladeIplBootPriorityEx': ['bayNumber:int', 'bladeIplBootArrayEx:iplBootPriorityArrayEx'],
 'setBladeMezzClpStrings': ['bayNumber:int', 'mezzNumber:int', 'bladeMezzClpStrings:bladeClpMezzStringArray'],
 'setBladeMpEv': ['bayNumber:int', 'bladeMpEv:bladeMpEv'],
 'setBladeOneTimeBoot': ['bayNumber:int', 'oneTimeBootDevice:string', 'oneTimeBootAgent:string', 'oneTimeBypassF1F2Messages:boolean'],
 'setBladeOneTimeBootEx': ['bayNumber:int', 'oneTimeBootDevice:string', 'oneTimeBootAgent:string', 'oneTimeBypassF1F2Messages:boolean', 'toggleBootMode:boolean'],
 'setBladeOneTimeBootUefiTarget': ['bayNumber:int', 'uefiTargetDevId:int'],
 'setBladePower': ['bayNumber:int', 'power:string'],
 'setBladePowerEfficiencyMode': ['bayNumber:int', 'efficiencyMode:string'],
 'setBladeSignature': ['bayNumber:int'],
 'setBladeSignatureHold': ['bayNumber:int'],
 'setBladeSystemClpStrings': ['bayNumber:int', 'strings:bladeClpStringArray'],
 'setBladeUid': ['bayNumber:int', 'uid:string'],
 'setCertificate': ['certificate:string'],
 'setCertificateEx': ['bayNumber:int', 'certificate:string'],
 'setEbipaDnsServers': ['ebipaDevice:string', 'ipAddress1:string', 'ipAddress2:string', 'ipAddress3:string'],
 'setEbipaDomain': ['ebipaDevice:string', 'domain:string'],
 'setEbipaGateway': ['ebipaDevice:string', 'ipAddress:string'],
 'setEbipaIpAddress': ['ebipaDevice:string', 'ipAddress:string'],
 'setEbipaNetmask': ['ebipaDevice:string', 'ipAddress:string'],
 'setEbipaNtpServers': ['ebipaDevice:string', 'ipAddress1:string', 'ipAddress2:string'],
 'setEbipav6Info': ['ebipav6Info:ebipav6Info'],
 'setEbipav6InfoEx': ['ebipav6InfoEx:ebipav6InfoEx'],
 'setEnclosureAssetTag': ['assetTag:string'],
 'setEnclosureIpv6Settings': ['enclIpv6Enable:boolean', 'enclDhcpv6Enable:boolean', 'enclRouterAdvEnable:boolean', 'enclSlaacEnable:boolean'],
 'setEnclosureName': ['enclosureName:string'],
 'setEnclosurePowerCollectionInfo': ['enclosurePowerCollectionMode:string', 'sampleCount:int'],
 'setEnclosureTime': ['dateTime:string'],
 'setEnclosureTimeZone': ['timeZone:string'],
 'setEnclosureUid': ['uid:string'],
 'setEnclosureUsbMode': ['mode:string'],
 'setErsMaintenance': ['enabled:boolean', 'minutes:unsignedInt'],
 'setErsOnlineRegistrationComplete': [],
 'setErsProxyUrl': ['ersProxyUrl:string', 'ersProxyPort:int', 'ersProxyUsername:string', 'ersProxyPassword:string'],
 'setFipsEnabled': ['enable:boolean'],
 'setFipsMode': ['fipsMode:string', 'password:string'],
 'setFirmwareManagementBays': ['baySelection:enclosureBaysSelection'],
 'setFirmwareManagementEnabled': ['enabled:boolean'],
 'setFirmwareManagementForceDowngrade': ['enabled:boolean'],
 'setFirmwareManagementIsoUrl': ['isoUrl:string'],
 'setFirmwareManagementPolicy': ['updatePolicy:int'],
 'setFirmwareManagementPowerPolicy': ['powerPolicy:int'],
 'setFirmwareManagementSchedule': ['date:string', 'time:string'],
 'setHpSimTrustMode': ['trustMode:string'],
 'setInterconnectTrayAdminPassword': ['bayNumber:int'],
 'setInterconnectTrayFactory': ['bayNumber:int'],
 'setInterconnectTrayPower': ['bayNumber:int', 'on:boolean'],
 'setInterconnectTrayUid': ['bayNumber:int', 'uid:string'],
 'setInterconnectTrayVendorInfoBlock': ['bayNumber:int', 'blockNumber:int', 'blockData:hexBinary'],
 'setIpConfigDhcp': ['bayNumber:int', 'dynDns:boolean'],
 'setIpConfigDhcpIpv6': ['bayNumber:int', 'enable:boolean'],
 'setIpConfigIpv6': ['bayNumber:int', 'enable:boolean'],
 'setIpConfigStatic': ['bayNumber:int', 'ipAddress:string', 'netmask:string', 'gateway:string', 'dns1:string', 'dns2:string'],
 'setLcdButtonLock': ['buttonLock:boolean'],
 'setLcdProtectionPin': ['lcdPin:string'],
 'setLcdUserNotes': ['lcdUserNotesLine1:string', 'lcdUserNotesLine2:string', 'lcdUserNotesLine3:string', 'lcdUserNotesLine4:string', 'lcdUserNotesLine5:string', 'lcdUserNotesLine6:string'],
 'setLdapGroupBayAcl': ['ldapGroup:string', 'acl:string'],
 'setLdapGroupDescription': ['ldapGroup:string', 'description:string'],
 'setLdapInfo': ['directoryServerAddress:string', 'directoryServerSslPort:short', 'searchContext1:string', 'searchContext2:string', 'searchContext3:string', 'userNtAccountNameMapping:boolean'],
 'setLdapInfo2': ['directoryServerAddress:string', 'directoryServerSslPort:int', 'userNtAccountNameMapping:boolean', 'searchContexts:ldapSearchContexts'],
 'setLdapInfo3': ['directoryServerAddress:string', 'directoryServerSslPort:int', 'directoryServerGCPort:int', 'userNtAccountNameMapping:boolean', 'searchContexts:ldapSearchContexts'],
 'setLdapInfoEx': ['directoryServerAddress:string', 'directoryServerSslPort:int', 'searchContext1:string', 'searchContext2:string', 'searchContext3:string', 'userNtAccountNameMapping:boolean'],
 'setLinkFailoverEnabled': ['enabled:boolean'],
 'setLinkFailoverInterval': ['interval:int'],
 'setLoginBannerSettings': ['bannerEnabled:boolean', 'bannerText:string'],
 'setMinimumPasswordLength': ['length:int'],
 'setNetworkProtocol': ['protcol:string', 'enable:boolean'],
 'setNetworkProtocols': ['http:boolean', 'ssh:boolean', 'telnet:boolean', 'xmlReply:boolean', 'strongEncryption:boolean'],
 'setNtpPoll': ['secs:int'],
 'setNtpPrimary': ['ipAddress:string'],
 'setNtpSecondary': ['ipAddress:string'],
 'setOaDefaultGateway': ['bayNumber:int', 'ipAddress:string'],
 'setOaDns': ['bayNumber:int', 'dns1:string', 'dns2:string'],
 'setOaDnsIpv6': ['bayNumber:int', 'dns1:string', 'dns2:string'],
 'setOaIpv6Settings': ['bayNumber:int', 'ipv6Enable:boolean', 'dhcpv6Enable:boolean', 'routerAdvEnable:boolean'],
 'setOaIpv6StaticDefaultGateway': ['bayNumber:int', 'ipv6Address:string'],
 'setOaIpv6StaticRoutes': ['bayNumber:int', 'ipv6StaticRouteDestination1:string', 'ipv6StaticRouteDestination2:string', 'ipv6StaticRouteDestination3:string', 'ipv6StaticRouteGateway1:string', 'ipv6StaticRouteGateway2:string', 'ipv6StaticRouteGateway3:string'],
 'setOaName': ['bayNumber:int', 'oaName:string'],
 'setOaNetworkStaticIpv6': ['bayNumber:int', 'staticIpv6Address1:string', 'staticIpv6Address2:string', 'staticIpv6Address3:string', 'staticIpv6Dns1:string', 'staticIpv6Dns2:string'],
 'setOaOverrideDHCPDomainNameState': ['bayNumber:int', 'enabled:boolean'],
 'setOaSessionTimeout': ['timeout:int'],
 'setOaUid': ['bayNumber:int', 'uid:string'],
 'setOaUserDomainName': ['bayNumber:int', 'userDomainName:string'],
 'setOaUserDomainNameAndState': ['bayNumber:int', 'userDomainName:string', 'enabled:boolean'],
 'setOaVcmMode': ['isVcmMode:boolean', 'vcmUrl:string', 'vcmDomainId:string', 'vcmDomainName:string'],
 'setPowerCapConfig': ['config:powerCapConfig'],
 'setPowerCapExtConfig': ['config:powerCapExtConfig'],
 'setPowerConfigInfo': ['redundancyMode:string', 'powerCeiling:int', 'dynamicPowerSaverEnabled:boolean'],
 'setPowerdelayInterconnectSettings': ['powerdelaySettings:powerdelayBayArray'],
 'setPowerdelayServerSettings': ['powerdelaySettings:powerdelayBayArray'],
 'setRackName': ['rackName:string'],
 'setRemoteSyslogEnabled': ['enabled:boolean'],
 'setRemoteSyslogPort': ['port:int'],
 'setRemoteSyslogServer': ['server:string'],
 'setRouterAdvertisementIpv6': ['bayNumber:int', 'enable:boolean'],
 'setSnmpCommunity': ['ro:string', 'rw:string'],
 'setSnmpContact': ['contact:string'],
 'setSnmpEngineId': ['engineId:string'],
 'setSnmpLocation': ['location:string'],
 'setSnmpReadCommunity': ['ro:string'],
 'setSnmpWriteCommunity': ['rw:string'],
 'setSolutionsId': ['solutionsID:string'],
 'setSshKeys': ['sshKeys:string'],
 'setSslSettings': ['sslSettingsInfo:sslSettingsInfo'],
 'setStaticIpv6': ['bayNumber:int', 'ipAddress:string', 'prefix:int', 'add:int'],
 'setStrictPasswordsEnabled': ['enabled:boolean'],
 'setUserBayAcl': ['username:string', 'acl:string'],
 'setUserCertificate': ['username:string', 'certificate:string'],
 'setUserContact': ['username:string', 'contact:string'],
 'setUserFullname': ['username:string', 'fullname:string'],
 'setUserPassword': ['username:string', 'password:string'],
 'setVariable': ['variableKey:string', 'variableValue:string'],
 'setVcmIpv6UrlList': ['urlList:urlArray'],
 'setVcmOaMinFwVersion': ['version:string'],
 'setVlanInfo': ['vlanInfo:vlanInfo'],
 'setWizardComplete': ['wizardStatus:string'],
 'submitMpRibcl': ['bayArray:bayArray', 'requestRibcl:string', 'maxResponseSize:int'],
 'subscribeForEvents': [],
 'syncOaRomEnhanced': [],
 'testAlertmail': [],
 'testErs': [],
 'testLdap': ['username:string', 'password:string'],
 'testRemoteSyslog': [],
 'testSnmp': [],
 'unSubscribeForEvents': ['pid:int'],
 'updateProLiantMp': ['bayArray:bayArray', 'iLoImageUrl:string', 'crc32:string'],
 'uploadFile': ['fileType:string', 'file:base64Binary'],
 'userExists': ['username:string'],
 'userLogIn': ['username:string', 'password:string'],
 'userLogOut': [],
 'withdrawLcdQuestion': [],
 'writeFirmwareInternal': ['oa:int']
}

anonymous_methods = [
    'getCurrentAccessLevel',
    'getCurrentUserInfo',
    'getDomainInfo',
    'getEnclosureNetworkInfo',
    'getFirmwareManagementLog',
    'getInterconnectTrayVcmInfoArray',
    'getKvmInfo',
    'getLanguages',
    'getLdapTestStatus',
    'getOaId',
    'getOaSessionTimeout',
    'getOaVcmMode',
    'getRackTopology',
    'getRackTopology2',
    'getSaPCIList',
    'getSoapInterfaceInfo',
    'getSolutionsId',
    'getSslCertificateInfo',
    'getSslSettings',
    'getTimeZones',
    'getTwoFactorAuthenticationConf',
    'getVcmIpv6UrlList',
    'getVcmOaMinFwVersion',
    'getVlanInfo',
]
anonymous_methods = { name:True for name in anonymous_methods }

def param_int(root, name, val):
    root.append(H.__getattr__(name)(str(int(val))))
    return root
    
def param_str(root, name, val):
    root.append(H.__getattr__(name)(str(val)))
    return root

def param_boolean(root, name, val):
    if isinstance(val, int):
        val = val != 0
    elif val is None:
        val = False
    elif not isinstance(val, bool):
        raise ParameterException("boolean parameter must be bool, int or None")
    root.append(H.__getattr__(name)('true' if val else 'false'))
    return root

def make_bay_array(rng):
    arr = H.bayArray()
    for n in rng:
        arr.append(H.bay(str(int(n))))
    return arr

def param_bayArray(root, name, val):
    if isinstance(val, int):
        root.append(H.bayArray(H.bay(str(val))))
    elif isinstance(val, list):
        root.append(make_bay_array(val))
    elif sys.version_info.major > 2 and isinstance(val, range):
        root.append(make_bay_array(val))
    else:
        raise ParameterException("bayArray value must be int, range or list of integers")
    return root

_supported_types = {
 'int': param_int,
 'byte': param_int,
 'short': param_int,
 'unsignedInt': param_int,
 'string': param_str,
 'boolean': param_boolean,
 'bayArray': param_bayArray,
}
_unsupported_types ={
 'base64Binary': True,
 'hexBinary': True,
 'bladeClpMezzStringArray': True,
 'bladeClpStringArray': True,
 'bladeIplArray': True,
 'bladeMpCredentials': True,
 'bladeMpEv': True,
 'ebipaConfig': True,
 'ebipaDevInfo': True,
 'ebipav6Info': True,
 'ebipav6InfoEx': True,
 'enclosureBaysSelection': True,
 'ipAddressArray': True,
 'iplBootPriorityArrayEx': True,
 'ldapSearchContexts': True,
 'powerCapConfig': True,
 'powerCapExtConfig': True,
 'powerdelayBayArray': True,
 'sslSettingsInfo': True,
 'urlArray': True,
 'vlanInfo': True,
 'x509CertificateData': True,
 'x509CertificateDataEx': True
}

def _prepare_params(method, root, args, values):
    if method not in methods:
        raise ParameterException("Unsupproted method specified: %s" % method)
    params = methods[method]
    for pidx in range(len(params)):
        name, ptype = params[pidx]
        if pidx < len(args):
            value = args[pidx]
        elif name not in values:
            raise ParameterException("Parameter '%s' is missing for method '%s'" % (name, method))
        else:
            value = values[name]
        if ptype not in _supported_types:
            raise ParameterException("Type '%s' of parameter '%s' in method '%s' is not supported yet." % (ptype, name, method))
        _supported_types[ptype](root, name, value)
    
def _call_method(self, name, args, kwargs):
    req = H.__getattr__(name)()
    _prepare_params(name, req, args, kwargs)
    data = self.send_request(req)
    return data

def _make_method(name):
    def _method(self, *args, **kwargs):
        return _call_method(self, name, args, kwargs)
    _method.__name__ = name
    params = methods[name]
    if len(params) == 0:
        _method.__doc__ = '%s(self)' % name
    else:
        _method.__doc__ = '%s(self, %s)' % (name, ', '.join([v[0]+': ' + v[1] for v in params]))
    return _method
        
def _import_methods(methods):
    for name, params in methods.items():
        for i in range(len(params)):
            params[i] = tuple(params[i].split(':'))
        setattr(HPOA, name, _make_method(name))
            
_import_methods(methods)

if __name__ == "__main__":
    import getpass
    import sys
    import requests
    from pprint import pprint as pp
    import hpoa

    def po(data):
        print(hpoa.etree.tostring(data, pretty_print=True).decode('utf-8'))

    if len(sys.argv) < 2:
        print("Usage: %s <OA address> [username]" % sys.argv[0])
        sys.exit(1)

    address = sys.argv[1]
    username = sys.argv[2] if len(sys.argv) > 2 else None

    requests.packages.urllib3.disable_warnings()
    try:
        # Have to disable DH to avoid SSL error: [SSL: DH_KEY_TOO_SMALL] dh key too small
        if sys.version_info.major > 2:
            requests.packages.urllib3.util.ssl_.DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
        else:
            requests.packages.urllib3.util.ssl_._DEFAULT_CIPHERS += ':HIGH:!DH:!aNULL'
    except:
        pass

    hpoa.logging.basicConfig(level=hpoa.logging.ERROR)
    hpoa.logging.getLogger().setLevel(hpoa.logging.DEBUG)
    #hpoa.logging.getLogger().setLevel(hpoa.logging.CRITICAL)

    if username is not None:
        password = getpass.getpass('Password:')
        api = hpoa.HPOA(address, username, password)
        print("Authorize to OA...")
    else:
        api = hpoa.HPOA(address)
        print("Anonymous login...")
    
    api.login()

    print("Get Rack Topology...")
    po(api.getRackTopology2())

    if username is None:
        sys.exit(0)

    print("Get interconnect modules...")
    po(api.get_interconnect_info())

    print("Get blade by bay number...")
    po(api.getBladeInfo(1))

    print("Get OA network info with named parameter...")
    po(api.getOaSessionArray(bay=1))

    api.logout()
