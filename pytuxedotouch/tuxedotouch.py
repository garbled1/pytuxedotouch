import asyncio
import time
import hmac
import hashlib
import logging
import httpx
import json
import ssl
import re
from bs4 import BeautifulSoup
from base64 import b64decode
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from const import (
    HOME_URL,
    HTMLAPI_URL,
    HEADER_PRE,
    API_URL,
    ARMING_CODES,
    OCCUPANCY_CODES,
)

"""
This module will communicate with a Tuxedo Touch Wifi module from Honeywell.
This is only tested on the most recent firmware, previous ones did not have
as much "encryption".
"""

logger = logging.getLogger(__name__)


class TuxAESCipher:
    def __init__(self, key, iv):
        self.key = key
        self.iv = iv

    def encrypt(self, data):
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        encdata = self.cipher.encrypt(pad(data.encode('utf-8'),
                                          AES.block_size))
        return b64encode(encdata)

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
        return unpad(self.cipher.decrypt(raw), AES.block_size)


class TuxedoTouchWiFi:
    def __init__(self, hostname, username, password):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.cjar = None
        self.api_key_enc = None
        self.api_iv_enc = None
        self.api_key_bytes = None
        self.api_iv_bytes = None

        # Debugging
        logging.basicConfig(level=logging.DEBUG)

        # The device uses an ancient DH key that is too small, and self signed
        ssl_context = httpx.create_ssl_context(verify=False)
        ssl_context.options ^= ssl.OP_NO_TLSv1_1
        ssl_context.set_ciphers('TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:RSA+AESGCM:RSA+AES:!aNULL:!eNULL:!MD5HIGH:!DH:!aNULL')
        self.client = httpx.AsyncClient(base_url=f'https://{self.hostname}',
                                        verify=ssl_context)

    def make_digest512(sekf, message, key):
        """ Digest message into sha512 hex."""
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')

        digester = hmac.new(key, message, hashlib.sha512)
        return(digester.hexdigest())

    def make_digest1(self, message, key):
        """ Digest message into sha1 hex."""
        key = bytes(key, 'UTF-8')
        message = bytes(message, 'UTF-8')

        digester = hmac.new(key, message, hashlib.sha1)
        return(digester.hexdigest())

    def validate_mac(self, macaddr, func):
        """ Validate a mac address is sane."""
        macaddr = macaddr.replace(':', '')
        macaddr = macaddr.upper()
        pattern = re.compile('^[0-9A-F-]+$')
        if not re.search(pattern, macaddr):
            logging.error(f'Bad macaddr in {func}')
            return None
        return macaddr

    async def disconnect(self):
        """ Disconnect from Tuxedo."""
        self.cjar = None
        self.api_key_enc = None
        self.api_iv_enc = None
        self.api_key_bytes = None
        self.api_iv_bytes = None

        await self.client.aclose()

    async def initial_login(self):
        """ Login, get cookie."""
        logger.info('Performing initial login to TuxedoTouch')
        r = await self.client.get(HOME_URL)
        if r.status_code != 200:
            logger.error('Initial URL failed, cannot find device')
            return False
        cjar = r.cookies
        header = r.headers
        user = self.make_digest512(self.username, header['Random'])
        password = self.make_digest512(self.username + self.password,
                                       header['Random'])
        payload = {
            'log': user,
            'log1': password,
            'identity': header['RandomId'],
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Connection': 'keep-alive',
        }

        rr = await self.client.post(HOME_URL, headers=headers, data=payload,
                                    cookies=cjar)
        if rr.status_code != 200:
            logger.error('Could not retrieve login cookie')
            return False
        self.cjar = rr.history[0].cookies
        return True

    async def get_enc_keys(self):
        """ Get the crazy 'encryption' keys from the device."""
        if self.cjar is None:
            logger.error('No cookie, not logged in')
            if not self.initial_login():
                return False

        r = await self.client.post(HTMLAPI_URL, cookies=self.cjar)
        soup = BeautifulSoup(r.text, 'html.parser')
        readit = soup.find(id='readit')
        if readit is None:
            logger.error('Could not find encryption keys')
            return False

        readit_val = readit.get('value')
        self.api_key_enc = readit_val[:64]
        self.api_iv_enc = readit_val[64:96]
        self.api_key_bytes = bytes.fromhex(self.api_key_enc)
        self.api_iv_bytes = bytes.fromhex(self.api_iv_enc)
        return True

    async def post_api(self, url, data):
        """ Handle a post."""
        if self.cjar is None:
            if not self.initial_login():
                return None
        if self.api_key_enc is None:
            if not self.get_enc_keys():
                return None

        if data is not None and len(data) > 0:
            d_to_send = TuxAESCipher(self.api_key_bytes, self.api_iv_bytes).encrypt(data)
            post_data = {
                'param': d_to_send,
                'len': len(d_to_send),
                'tstamp': int(time.time()),
            }

        headers = {
            'authtoken': self.make_digest1(HEADER_PRE + url, self.api_key_enc),
            'identity': self.api_iv_enc,
        }

        if data is not None and len(data) > 0:
            r = await self.client.post(API_URL + url, headers=headers,
                                       data=post_data, cookies=self.cjar)
        else:
            r = await self.client.post(API_URL + url, headers=headers,
                                       cookies=self.cjar)

        if r.status_code == 405:
            logging.error(f'Method not allowed at url {url}')
            return None
        if r.status_code == 401:
            logging.error(f'Unauthorized at url {url}')
            return None
        if r.status_code != 200:
            logging.error(f'Unknown error in post_api status={r.status_code}')
            return None
        r_data = json.loads(r.text)
        return TuxAESCipher(self.api_key_bytes, self.api_iv_bytes).decrypt(r_data['Result']).decode('utf-8')

    # Remaining API calls, in order as they appear on the tuxedoapi.html page.

    async def Register(self, macaddr):
        """
        -- Register the Client.This will send the Client Register Command.
        Example: http://<tuxedop ip>:<port>/system_http_api/API_REV01/Registration/Register?mac=[MAC ID of the accessing device max 17 characters formats (xx-xx-xx-xx-xx-xx or xxxxxxxxxx)]&operation=set. HTTP Header parameter "authtoken" has to be added to the request. "authtoken" parameter should have the value as "MACID:<Your Device MAC>,Path:API_REV01/Registration/Register" and should be hashed with HMACSHA1 alogrothim
        TYPEID

        TUXEDO=1;
        PC=2;
        MOBILEPHONE=3;
        TABLET=4;
        CONTROLLER=5;
        AUDIOPLAYER=6;
        VIDEOPLAYER=7;
        TV=8;
        """
        mac = self.validate_mac(macaddr, 'Register')
        if mac is None:
            return None

        d_to_send = f'mac={mac}&operation=set'
        data = await self.post_api('/Register', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def Unregister(self, macaddr):
        """
        -- Unregister the Client.This will send the Client Unregister Command.
        Example: http://<tuxedop ip>:<port>/system_http_api/API_REV01/Registration/Unregister?token=[Device MAC used during register]&operation=set
        Authentication token should be added as part of authtoken http header (Authentication token recieved during registeration operation. Not applicable for browser clients)
        """
        mac = self.validate_mac(macaddr, 'Unregister')
        if mac is None:
            return None

        d_to_send = f'token={mac}&operation=set'
        data = await self.post_api('/Unregister', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def ArmWithCode(self, arming, partition, ucode):
        """
        -- This service will ARM the System in AWAY/STAY/NIGHT mode.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedSecurity/ArmWithCode?arming=AWAY,STAY,NIGHT&pID=1 or 2 or 3...&ucode=Valid User Code&operation=set
        """
        if arming not in ARMING_CODES:
            logger.error(f'Invalid arming code in ArmWithCode {arming}')
            return None
        if partition < 1 or partition > 8:
            logger.error(f'Invalid partition {partition} in ArmWithCode')
            return None

        d_to_send = f'arming={arming}&pID={partition}&ucode={ucode}&operation=set'
        data = await self.post_api('/AdvancedSecurity/ArmWithCode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def DisarmWithCode(self, partition, ucode):
        """
        -- This command will DISARM The System with the user code entered by the client
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedSecurity/Disarm?pID=1 or 2 or 3...&ucode=Valid User Code&operation=set
        """
        if partition < 1 or partition > 8:
            logger.error(f'Invalid partition {partition} in ArmWithCode')
            return None

        d_to_send = f'pID={partition}&ucode={ucode}&operation=set'
        data = await self.post_api('/AdvancedSecurity/DisarmWithCode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def setDoorBell(self):
        """
        -- This Service will simulate the doorbell press action.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedAutomation/DoorBell/setDoorBell
        """
        data = await self.post_api('/AdvancedAutomation/DoorBell/setDoorBell',
                                   None)
        if data is not None:
            return json.loads(data)
        return None

    async def getDoorBell(self):
        """
        -- This Service will return the status of the door bell. It will get the latest doorbell event if occured. Once the event status is read, this event status will be cleared from the system.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedAutomation/DoorBell/getDoorBell
        """
        data = await self.post_api('/AdvancedAutomation/DoorBell/getDoorBell',
                                   None)
        if data is not None:
            return json.loads(data)
        return None

    async def GetCameraList(self):
        """
        -- This service will get all the camera's .
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedMultimedia/GetCameraList?operation=get
        """
        data = await self.post_api('/GetCameraList', None)
        if data is not None:
            return json.loads(data)
        return None

    async def DiscoverCamera(self):
        """
        -- This service will initiate a discovery in the home network.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedMultimedia/DiscoverCamera?operation=get
        """
        data = await self.post_api('/DiscoverCamera', None)
        if data is not None:
            return json.loads(data)
        return None

    # Undocumented commands:
    # /AdvancedMultimedia/SetCameraView
    # /AdvancedMultimedia/ZoomCamera
    # /AdvancedMultimedia/TriggerCameraRecord
    # /AdvancedMultimedia/GetVideoEvents

    async def AddDeviceMAC(self, dtype, macaddr):
        """
        -- This Allowed to add/enroll authenticated device MAC ID for remote access. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Registration/AdddeviceMAC?MAC=<DeviceMACID>
        """
        mac = self.validate_mac(macaddr, 'AddDeviceMAC')
        if mac is None:
            return None

        d_to_send = f'Type={dtype}&devMAC={mac}&operation=set'
        data = await self.post_api('/Administration/AddDeviceMAC', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def RemoveDeviceMac(self, macaddr):
        """
        -- This Allowed to remove the previously added device MAC ID for remote access. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Registration/RemovedeviceMAC?MAC=<DeviceMACID>
        """
        mac = self.validate_mac(macaddr, 'RemoveDeviceMAC')
        if mac is None:
            return None

        d_to_send = f'devMAC={mac}&operation=set'
        data = await self.post_api('/Administration/RemoveDeviceMAC', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def ViewEnrolledDeviceMAC(self):
        """
        -- This Allowed to remove the previously added device MAC ID for remote access. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Registration/ ViewenrolleddeviceMAC?MAC=<DeviceMACID>
        """
        data = await self.post_api('/Administration/ViewEnrolledDeviceMAC', None)
        if data is not None:
            return json.loads(data)
        return None

    async def RevokeKeys(self, macaddr):
        """
        -- This service is used to revoke the private and public key associated with a device mac. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Administration/RevokeKeys?devMAC=<MAC ID>&operation=set
        """
        mac = self.validate_mac(macaddr, 'RevokeKeys')
        if mac is None:
            return None

        d_to_send = f'devMAC={mac}&operation=set'
        data = await self.post_api('/Administration/RevokeKeys', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def AddIPURL(self, macaddr, ip, port, url, qstring):
        """
        -- This command is used to add IP & call back URL address of the client device. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Administration/AddIPURL?mac=<MAC ID>&IP=<Device IP>&url=<Call back server link>&operation=set
        """
        mac = self.validate_mac(macaddr, 'AddIPURL')
        if mac is None:
            return None

        d_to_send = f'mac={mac}&ip={ip}&port={port}&url={url}&qstring={qstring}&operation=set'
        data = await self.post_api('/Administration/AddIPURL', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def UpdateIPURL(self, macaddr, ip, url):
        """
        Undocumented
        """
        mac = self.validate_mac(macaddr, 'UpdateIPURL')
        if mac is None:
            return None

        d_to_send = f'mac={mac}&ip={ip}&url={url}&operation=set'
        data = await self.post_api('/Administration/UpdateIPURL', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def ViewIPURL(self, macaddr):
        """
        -- This command is used to view the IP and URL address associated with a MAC. This service only accessible in Local Area network. This command requires Admin authorization.
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/Administration/ViewIPURL?mac=<Device MAC ID>&operation=set
        """
        mac = self.validate_mac(macaddr, 'ViewIPURL')
        if mac is None:
            return None

        d_to_send = f'mac={mac}&ip={ip}&url={url}&operation=set'
        data = await self.post_api('/Administration/ViewIPURL', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def DeleteAllCameras(self):
        """
        -- This Service will delete all the cameras from the list
        Example : http://<Tuxedo IP>:<port>/system_http_api/API_REV01/AdvancedMultimedia/DeleteAllCameras?operation=get
        """
        data = await self.post_api('/Administration/DeleteAllCameras', None)
        if data is not None:
            return json.loads(data)
        return None

    async def GetDeviceList(self, category):
        """
        -- Get the latest device list with all or some of devices enrolled to Tuxedo. Default gets all the devices in all categories, or pass a category parameter to get only a specific category of device list.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetDeviceList?category=[category:optional]&operation=set
        Catergories
        All(default)
        AllZwaveDevices
        Cameras
        Lights
        Thermostats
        Locks
        Shades
        OneTouchScene/AllScenes
        Sensors (future)
        Appliances (future)
        EMON Electric meter (future).
        """
        d_to_send = f'category={category}&operation=set'
        data = await self.post_api('/GetDeviceList', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetSecurityStatus(self):
        """
        -- Get the default home partition status, Partition ID is optional.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetSecurityStatus?operation=get
        """
        data = await self.post_api('/GetSecurityStatus', None)
        if data is not None:
            return json.loads(data)
        return None

    async def SetSecurityArm(self, arming, partition):
        """
        -- Use this service to change the partition status.Default is AWAY and partition 1.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetSecurityArm?arming=[AWAY,STAY,NIGHT]&pID=[Partition ID (1-8)]&operation=set
        """
        if arming not in ARMING_CODES:
            logger.error(f'Invalid arming code in ArmWithCode {arming}')
            return None
        if partition < 1 or partition > 8:
            logger.error(f'Invalid partition {partition} in ArmWithCode')
            return None

        d_to_send = f'arming={arming}&pID={partition}&operation=set'
        data = await self.post_api('/SetSecurityArm', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetOccupancyMode(self):
        """
        -- Get the occupancy status from automation mode.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetOccupancyMode?operation=get
        """
        data = await self.post_api('/GetOccupancyMode', None)
        if data is not None:
            return json.loads(data)
        return None

    async def SetOccupancyMode(self, omode):
        """
        -- This Service is used to set the occupancy status for automation mode
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetOccupancyMode?omode=[HOME,AWAY/CLOSE,NIGHT]&operation=set
        """
        if omode not in OCCUPANCY_CODES:
            logger.warning(f'Invalid occupancy mode {omode}')
            return None
        d_to_send = f'omode={omode}&operation=set'
        data = await self.post_api('/SetOccupancyMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetLightStatus(self, nodeID):
        """
        -- This Service will get the status off a particular binary light (Nodeid,Device Name,Device Type and Status [Binary Switch 0-OFF,255-ON][Multilevel Switch 0-OFF, 1 to 99-ON)
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetLightStatus?nodeID=[Device ID assigned in Tuxedo Home Automation]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetLightStatus')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetLightStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetLight(self, nodeID, percent):
        """
        -- This Service will set the status off a particular binary or dimmer light
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetLight?nodeID=[Device ID assigned in Tuxedo Home Automation]&percent=[percent=ON, OFF, DIM1,…
DIM10]&operation=set
        Where DIM1-DIM10 equal to 10 to 99.

        I'm not clear if this should be a string or an int? I suspect it needs
        to be DIMxx where x is an integer? and therefore a string...
        totally untested.
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetLight')
            return None
        d_to_send = f'nodeID={nodeID}&percent={percent}&operation=set'
        data = await self.post_api('/SetLight', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatMode(self, nodeID):
        """
        -- This service will return the mode of particular thermostat(Nodeid,Device Name,Device Type and Mode [OFF,HEAT,COOL,AUTO,SAVECOOL,SAVEHEAT])
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatMode?nodeID=[Device ID assigned in Tuxedo Home Automation]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatMode')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatSetPoint(self, nodeID):
        """
        -- This service will give Heat and Cool Setpoint of particular thermostat(Nodeid,Device Name,Device Type,Heat Setpoint,Cool Setpoint,Save Heat,Save Cool)
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatSetPoint?nodeID=[Device ID assigned in Tuxedo Home Automation]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatSetPoint')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatSetPoint', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatEnergyMode(self, nodeID):
        """
        -- This service will give the thermostat mode,Energy Save or Normal
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatEnergyMode?nodeID=[Device ID assigned in Tuxedo Home Automation]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatEnergyMode')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatEnergyMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetThermostatMode(self, nodeID, mode):
        """
        -- Use this service to change the thermostat mode [mode=OFF,HEAT,COOL,AUTO].Modes 0-OFF,1-HEAT,2-COOL,3-AUTO,11-SAVEHEAT,12-SAVECOOL.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetThermostatMode?nodeID=[Device ID assigned in Tuxedo Home Automation]&mode=
        [mode=OFF,HEAT,COOL,AUTO]&operation=set

        Again.  string or int?
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetThermostatMode')
            return None
        d_to_send = f'nodeID={nodeID}&mode={mode}&operation=set'
        data = await self.post_api('/SetThermostatMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetThermostatSetPoint(self, nodeID, mode, temp):
        """
        -- Use this service to change the Heat and Cool Setpoint of particular thermostat [mode=HEAT,COOL,SAVEHEAT,SAVECOOL].Modes 1-HEAT,2-COOL,11-SAVEHEAT,12-SAVECOOL.
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetThermostatSetPoint?nodeID=[Device ID assigned in Tuxedo Home Automation]&mode=
        [mode=HEAT,COOL,SAVEHEAT,SAVECOOL]&setPoint=[setpoint=temp_value]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetThermostatSetPoint')
            return None
        d_to_send = f'nodeID={nodeID}&mode={mode}&setPoint={temp}&operation=set'
        data = await self.post_api('/SetThermostatSetPoint', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetThermostatEnergyMode(self, nodeID, semode):
        """
        -- Use this service to change the thermostat mode to Energy Save or Normal[dev_id=node_ID], [energy_mode=NORMAL,ECO]
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetThermostatEnergyMode')
            return None
        d_to_send = f'nodeID={nodeID}&mode={semode}&operation=set'
        data = await self.post_api('/SetThermostatEnergyMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    # Undocumented commands:
    # SetThermostatSchedule
    # SetThermostatSetClock
    
    async def GetDoorLockStatus(self, nodeID):
        """
        -- Use this service to get the status of a particular doorlock
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetDoorLockStatus?nodeID=[Device ID assigned in Tuxedo Home Automation]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetDoorLockStatus')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetDoorLockStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetDoorLock(self, nodeID, control):
        """
        -- Use this service to set the status of a particular doorlock[LOCK or 1]
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetDoorLock?nodeID=[Device ID assigned in Tuxedo Home Automation]&cntrl=[LOCK,UNLOCK ]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetDoorLock')
            return None
        d_to_send = f'nodeID={nodeID}&cntrl={control}&operation=set'
        data = await self.post_api('/SetDoorLock', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetSceneList(self):
        """
        -- Use this command to retrieve all the Scenes
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetSceneList?operation=get
        """
        data = await self.post_api('/GetSceneList', None)
        if data is not None:
            return json.loads(data)
        return None

    async def ExecuteScene(self, sceneID):
        """
        -- Use this command to execute the scene
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/ExecuteScene?sceneID=[SceneID=1]&operation=set
        """
        if not isinstance(sceneID, int):
            logger.warning(f'Invalid sceneID {sceneID} in ExecuteScene')
            return None
        d_to_send = f'sceneID={sceneID}&operation=set'
        data = await self.post_api('/ExecuteScene', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatTemperature(self, nodeID):
        """
        -- This Service will retrieve the current temperature from the thermostat
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatTemperature?nodeID=[Device Node ID]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatTemperature')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatTemperature', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatFanMode(self, nodeID):
        """
        -- This Service will retrieve the current temperature from the thermostat
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatTemperature?nodeID=[Device Node ID]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatFanMode')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatFanMode', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetThermostatFullStatus(self, nodeID):
        """
        -- This Service will retrieve the current temperature from the thermostat
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetThermostatTemperature?nodeID=[Device Node ID]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetThermostatFullStatus')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetThermostatFullStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetWaterValveStatus(self, nodeID):
        """
        -- Use this service to get the status of a particular water valve control
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetWaterValveStatus?nodeID=[node_ID=dev_id]
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetWaterValveStatus')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetWaterValveStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetWaterValveStatus(self, nodeID, status):
        """
        -- Use this service to set the status of a particular water valve control
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetWaterValveStatus?nodeID=[node_ID=dev_id]&cntrl=[[Close or 1] or [Open or 255]]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetWaterValveStatus')
            return None
        d_to_send = f'nodeID={nodeID}&status={status}&operation=set'
        data = await self.post_api('/SetWaterValveStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def GetGarageDoorStatus(self, nodeID):
        """
        -- Use this service to get the status of a particular garage door control
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/GetGarageDoorStatus?nodeID=[node_ID=dev_id]
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in GetGarageDoorStatus')
            return None
        d_to_send = f'nodeID={nodeID}&operation=set'
        data = await self.post_api('/GetGarageDoorStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None

    async def SetGarageDoorStatus(self, nodeID, control):
        """
        -- Use this service to set the status of a particular garage door control
        Example : http://<tuxedop ip>:<port>/system_http_api/API_REV01/SetGarageDoorStatus?nodeID=[node_ID=dev_id]&cntrl=[[Close or 1] or [Open or 255]]&operation=set
        """
        if not isinstance(nodeID, int):
            logger.warning(f'Invalid nodeID {nodeID} in SetGarageDoorStatus')
            return None
        d_to_send = f'nodeID={nodeID}&cntrl={control}&operation=set'
        data = await self.post_api('/SetGarageDoorStatus', d_to_send)
        if data is not None:
            return json.loads(data)
        return None
