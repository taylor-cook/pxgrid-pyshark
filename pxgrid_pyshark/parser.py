import json
import binascii
import re
import logging
import pkg_resources
from user_agents import parse
import xml.etree.ElementTree as ET
from .ouidb import *

apple_os_json = 'db/apple-os.json'
models_json = 'db/models.json'
apple_os_data, models_data = {}, {}

macoui_url = 'https://standards-oui.ieee.org/'
macoui_raw_data_file = 'db/macoui.txt'
macoui_pipe_file = 'db/macoui.pipe'
macoui_database_file = 'db/macoui.db'
oui_manager= ouidb(macoui_url, macoui_raw_data_file, macoui_pipe_file, macoui_database_file)

logger = logging.getLogger(__name__)

def get_OUI(mac, manager):
    mac_prefix = mac.replace(':','')[:6].upper()
    vendor = manager.query_mac_address(mac_prefix)
    ## IF NO MATCH FOUND, CHECK IF MAC ADDRESS FOLLOWS RANDOMIZATION STANDARD
    if vendor is None:
        pattern = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$')
        if pattern.match(mac):
            # Check if the "U/L" bit is set in the first octet
            first_octet = int(mac[:2], 16)
            if (first_octet & 2) == 2:
                return 'Unknown (randomized MAC)'
    else:
        return vendor

def load_model_os_data():
    global models_data, models_json
    global apple_os_data, apple_os_json
    with open(apple_os_json, 'r') as file:
        json_data = file.read()
    apple_os_data = json.loads(json_data)
    with open(models_json, 'r') as file:
        json_data = file.read()
    models_data = json.loads(json_data)

## Vendor agnostic model and OS parsing
def parse_model_and_os(values, txt):
    values[8] = txt
    model_match = False
    ## For Apple (or randomized MAC Apple) devices, extract OS and model details from string
    if 'Apple' in values[5] or 'randomized' in values[5]:
        osx_index = txt.find('osxvers=')
        model_index = txt.find('model=')
        ## Parse the OSX details if included in txt value
        if osx_index != -1:
            end_index = txt.find("',",osx_index)
            if end_index != -1:
                values[7] = txt[osx_index:end_index]
            else:
                end_index = txt.find("'",osx_index)
                values[7] = txt[osx_index:end_index]
            if values[7] in apple_os_data:
                values[7] = apple_os_data[values[7]]      #Provide a more readable version of OSX
                values[15] = 50       # Weighted value of Apple OS detail (major ver only)
        if model_index != -1:
            end_index = txt.find("',",model_index)
            if end_index != -1:
                values[8] = txt[model_index:end_index]
            else:
                values[8] = txt[model_index:]
            ## Parse through model details of Apple devices only
            for model, result in models_data['Apple'].items():
                if values[8] == model:
                    model_match = True
                    values[6] = result
                    values[14], values[16] = 80, 80
        return values

    ## Look through models dict, first by OUI details
    for oui, models in models_data.items():
        if values[5].lower().startswith(oui.lower()):
            ## If there is an OUI match, search through the models provided
            for model, result in models.items():
                ## If model match found, record details of HW model and improve certainty
                if txt == model:
                    model_match = True
                    values[6] = result
                    values[14], values[16] = 80, 80
                    break               ## Exit for loop through models
        if model_match is True:
            break                       ## Exit for loop through OUIs
    ## If model data doesn't match any record, record model data and use lower certainty
    if model_match is not True:
        values[16] = 30
        #logger.debug(f'No model found: {values[0]}: {values[5]} - {txt}')
    return values

class parser:
    def __init__(self):
        self.apple_os_json = pkg_resources.resource_filename('pxgrid_pyshark',apple_os_json)
        self.models_json = pkg_resources.resource_filename('pxgrid_pyshark',models_json)
        self._initialize_database()
        # load_model_os_data()
    
    def _initialize_database(self):
        global apple_os_data, models_data
        with open(self.apple_os_json, 'r') as file:
            json_data = file.read()
        apple_os_data = json.loads(json_data)
        with open(self.models_json, 'r') as file:
            json_data = file.read()
        models_data = json.loads(json_data)

    def parse_mac_ip(self, packet):
        try:
            erspan_flag = False
            if 'erspan' in packet:
                erspan_flag = True
            if erspan_flag and packet['eth'].duplicate_layers:
                mac = packet['eth'].duplicate_layers[0].src
                vendor = get_OUI(mac, oui_manager)
            else:
                mac = packet['eth'].src
                vendor = get_OUI(mac, oui_manager)
            ### TO DO: MODIFY ACCORDINGLY FOR IPV6 ###
            if erspan_flag and packet['ip'].duplicate_layers:
                ip = packet['ip'].duplicate_layers[0].src
            else:
                ip = packet['ip'].src
            return mac, ip, vendor
        except AttributeError:
            return None, None, None

    def parse_http(self, packet):
        mac, ip, vendor = self.parse_mac_ip(packet)
        asset_values = ['']*11 + ['0']*8      # Create an empty list for potential values
        if mac is None:
            return None
        asset_values[0] = mac
        asset_values[5] = vendor
        if ip is not None:
            asset_values[2] = ip
        asset_values[1] = 'HTTP'
        try:
            layer = packet['http']

            ## IF UPNP DATA ADVERTISED BY THE ENDPOINT ##
            if 'location' in layer.field_names:
                upnp_url = layer.location

            if 'user_agent' in layer.field_names:
                ua_string = layer.user_agent
                #print(f'ua: {ua_string}')
                user_agent = parse(ua_string)
                if user_agent.os.family == 'Other' and 'Mac OS X' in ua_string:
                    asset_values[7] = 'Mac OS X'
                    asset_values[15] = 10
                elif user_agent.os.family != '':
                    asset_values[7] = user_agent.os.family
                    asset_values[15] = 10           #Weak score as often just generic OS type 'Windows'
                if user_agent.os.version_string != '':
                    asset_values[7] = user_agent.os.family + ' ' + user_agent.os.version_string
                    asset_values[15] = 30           # Still a weak score because OS details can be inaccurate (ex. 'OS X 10.15' reported on Mac running 14.2)
                ### TO DO: Currently overrides more specific mDNS value, need to include weighting ###
                if user_agent.device.brand is not None and user_agent.device.brand != 'Other':
                    if user_agent.device.model is not None and user_agent.device.model != '' and user_agent.device.model != 'User-Agent':
                        asset_values[8] = user_agent.device.model
                        asset_values[16] = 50
                
                if user_agent.is_pc is True:
                    asset_values[10] = 'Workstation'
                    asset_values[18] = 50
                elif user_agent.is_tablet is True:
                    asset_values[10] = 'Tablet'
                    asset_values[18] = 50
                elif user_agent.is_mobile is True:
                    asset_values[10] = 'Mobile'
                    asset_values[18] = 50
            if 'request.line' in layer.field_names:
                line = layer.line                                              # Store the request line as list
                result = [text for text in line if 'FriendlyName' in text]     # If 'FriendlyName' in the line items
                if result != []:
                    result_text = result[0]
                    pattern = re.compile(r': (.*?)\r\n')                #Grab the hostname value
                    match = pattern.search(result_text)
                    if match:
                        # print(f'Match: {match.group(1)[:-4]}')
                        asset_values[4] = match.group(1)[:-4]           #Remove the \r\n from the string
                        asset_values[12] = 50
                return asset_values
        except AttributeError:
            return None

    def parse_ssdp(self, packet):
        mac, ip, vendor = self.parse_mac_ip(packet)
        asset_values = ['']*11 + ['0']*8      # Create an empty list for potential values
        if mac is None:
            return None
        asset_values[0] = mac
        asset_values[5] = vendor
        if ip is not None:
            asset_values[2] = ip
        asset_values[1] = 'SSDP'
        try:
            layer = packet['ssdp']

            ## IF UPNP DATA ADVERTISED BY THE ENDPOINT ##
            if 'location' in layer.field_names:
                upnp_url = layer.location

            if 'user_agent' in layer.field_names:
                ua_string = layer.user_agent
                user_agent = parse(ua_string)
                if user_agent.os.family == 'Other' and 'Mac OS X' in ua_string:
                    asset_values[7] = 'Mac OS X'
                    asset_values[15] = 10
                elif user_agent.os.family != '':
                    asset_values[7] = user_agent.os.family
                    asset_values[15] = 10           #Weak score as often just generic OS type 'Windows'
                if user_agent.os.version_string != '':
                    asset_values[7] = user_agent.os.family + ' ' + user_agent.os.version_string
                    asset_values[15] = 50
                if user_agent.device.brand is not None and user_agent.device.brand != 'Other':
                    if user_agent.device.model is not None and user_agent.device.model != '':
                        asset_values[8] = user_agent.device.model
                        asset_values[16] = 50
                
                if user_agent.is_pc is True:
                    asset_values[10] = 'Workstation'
                    asset_values[18] = 50
                elif user_agent.is_tablet is True:
                    asset_values[10] = 'Tablet'
                    asset_values[18] = 50
                elif user_agent.is_mobile is True:
                    asset_values[10] = 'Mobile'
                    asset_values[18] = 50
                # print(asset_values)

            return asset_values
        except AttributeError:
            return None

    def parse_xml(self, packet):
        mac, ip, vendor = self.parse_mac_ip(packet)
        asset_values = ['']*11 + ['0']*8      # Create an empty list for potential values
        if mac is None:
            return None
        asset_values[0] = mac
        asset_values[5] = vendor
        if ip is not None:
            asset_values[2] = ip
        asset_values[1] = 'XML'
        try:
            layer = packet['XML']
            binary_xml = binascii.unhexlify(packet.xml_raw.value)  ## Convert the XML data raw into a string, which is in binary format
            root = ET.fromstring(binary_xml)

            ## TO DO: IMPROVE XML PARSING METHOD ##
            # xml_data = binary_xml.decode('utf-8')
            # root_xml = minidom.parseString(xml_data)
            # try:
            #     asset_values[5] = root_xml.getElementsByTagName('manufactuer')[0].firstChild.nodeValue
            #     asset_values[10] = root_xml.getElementsByTagName('modelName')[0].firstChild.nodeValue
            #     asset_values[8] = root_xml.getElementsByTagName('modelNumber')[0].firstChild.nodeValue
            #     asset_values[6] = root_xml.getElementsByTagName('modelDescription')[0].firstChild.nodeValue
            #     asset_values[9] = root_xml.getElementsByTagName('serialNumber')[0].firstChild.nodeValue
            #     print(asset_values)
            # except Exception as e:
            #     print(e)

            try:
                # Extract data from the XML
                asset_values[5] = root.find(".//{urn:schemas-upnp-org:device-1-0}manufacturer").text
                asset_values[13] = 80
                asset_values[10] = root.find(".//{urn:schemas-upnp-org:device-1-0}modelName").text
                asset_values[18] = 80
                asset_values[8] = root.find(".//{urn:schemas-upnp-org:device-1-0}modelNumber").text
                asset_values[16] = 80
                asset_values[6] = root.find(".//{urn:schemas-upnp-org:device-1-0}modelDescription").text
                asset_values[14] = 50
                asset_values[9] = root.find(".//{urn:schemas-upnp-org:device-1-0}serialNumber").text
                asset_values[17] = 80
            except Exception as e:
                logger.debug(f'Error processing {asset_values[1]} packet: {e}')
                pass
            return asset_values
        except AttributeError:
            return None
        
    def parse_sip(self, packet):
        mac, ip, vendor = self.parse_mac_ip(packet)
        asset_values = ['']*11 + ['0']*8      # Create an empty list for potential values
        if mac is None:
            return None
        asset_values[0] = mac
        asset_values[5] = vendor
        if ip is not None:
            asset_values[2] = ip
        asset_values[1] = 'SIP'
        try:
            layer = packet['sip']
            ua_index = layer.msg_hdr.find("User-Agent")
            if ua_index != -1:
                cr_index = layer.msg_hdr.find("\r\n",ua_index)
                asset_values[10] = layer.msg_hdr[ua_index+12:cr_index]
                asset_values[18] = 20
            return asset_values
        except AttributeError:
            return None

    def parse_mdns(self, packet):
        mac, ip, vendor = self.parse_mac_ip(packet)
        asset_values = ['']*11 + ['0']*8      # Create an empty list for potential values
        
        if mac is None:
            return None
        asset_values[0] = mac
        asset_values[5] = vendor
        if ip is not None:
            asset_values[2] = ip
        asset_values[1] = 'mDNS'
        try:
            layer = packet['mdns']
            if int(layer.answers) >0:
                for key in layer._all_fields['Answers']:
                    ## If an Apple device and an mDNS "device-info" advertisement, parse known attributes of endpoint
                    if layer._all_fields['Answers'][key]['dns.resp.type'] == '16' and 'device-info' in key:
                        asset_values[4] = layer._all_fields['Answers'][key]['dns.resp.name'].partition('.')[0]  #Return the name up to the first '.'
                        asset_values[12] = 80
                        dns_txt = str(layer._all_fields['Answers'][key]['dns.txt'])
                        asset_values = parse_model_and_os(asset_values, dns_txt)
                        return asset_values
                    
                    elif layer._all_fields['Answers'][key]['dns.resp.type'] == '16':
                        for item in layer._all_fields['Answers'][key]['dns.txt']:
                            if 'model=' in item or 'MDL=' in item or 'md=' in item or 'modelid=' in item or 'usb_MDL=' in item:
                                asset_values = parse_model_and_os(asset_values, item)
                            elif 'MFG=' in item or 'manufacturer=' in item:
                                asset_values[5] = item.partition('=')[2]   ## Return only the value after the '='
                                asset_values[13] = 50

                            elif 'UUID=' in item or 'serialNumber=' in item:
                                asset_values[9] = item.partition('=')[2]
                                asset_values[17] = 50
                            elif 'deviceid=' in item and asset_values[0] in item:
                                #Only store the "deviceid=" value if it is not the MAC address
                                if str(item.partition('=')[2]).lower() is not (asset_values[0]).lower():
                                    asset_values[3] = item.partition('=')[2]
                        return asset_values
            if int(layer.add_rr) > 0:
                for key in layer._all_fields['Additional records']:
                    if 'device-info' in key:
                        asset_values[4] = layer._all_fields['Additional records'][key]['dns.resp.name'].partition('.')[0]  #Return the name up to the first '.'
                        asset_values[12] = 80
                        dns_txt = str(layer._all_fields['Additional records'][key]['dns.txt'])
                        asset_values = parse_model_and_os(asset_values, dns_txt)
                        
                        return asset_values
                    elif 'local: type TXT' in key:
                        asset_values[4] = layer._all_fields['Additional records'][key]['dns.resp.name'].partition('.')[0]  #Return the name up to the first '.'
                        asset_values[12] = 80
                        dns_txt = layer._all_fields['Additional records'][key]['dns.txt']
                        if type(dns_txt) == list:
                            for entry in dns_txt:
                                if 'md=' in entry:
                                    asset_values = parse_model_and_os(asset_values, entry)
                        else:
                            if 'md=' in dns_txt:
                                asset_values = parse_model_and_os(asset_values, entry)
            return asset_values
        except AttributeError:
            logger.debug(f'AttributeError for {asset_values[1]} packet from {asset_values[0]}: {e}')
            return asset_values
        except TypeError as e:
            logger.debug(f'TypeError for {asset_values[1]} packet from {asset_values[0]}: {e}')
            return asset_values
