#!/usr/bin/env python
import sys
import uuid
import hashlib
import hmac
import json
import re
import datetime
import logging
import configparser

import base64

import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import binascii 
from time import sleep
from binascii import hexlify
import requests
from influxdb import InfluxDBClient
from flatten_json import flatten 

import xml.etree.ElementTree as ET

config = configparser.ConfigParser()
config.read('huawei.ini')

time = datetime.datetime.utcnow()

# Generate clientside nonce
def generate_nonce():
    return uuid.uuid4().hex + uuid.uuid4().hex

# Get session cookie
def setup_session(client, server):
    url = "http://%s/" % server
    response = client.get(url)
    response.raise_for_status()
    sleep(1)

# Calculate server-client proof, part of SCRAM algorithm
def get_client_proof(clientnonce, servernonce, password, salt, iterations):
    msg = "%s,%s,%s" % (clientnonce, servernonce, servernonce)
    salted_pass = hashlib.pbkdf2_hmac(
        'sha256', password, bytearray.fromhex(salt), iterations)
    client_key = hmac.new(b'Client Key', msg=salted_pass,
                          digestmod=hashlib.sha256)
    stored_key = hashlib.sha256()
    stored_key.update(client_key.digest())
    signature = hmac.new(msg.encode('utf_8'),
                         msg=stored_key.digest(), digestmod=hashlib.sha256)
    client_key_digest = client_key.digest()
    signature_digest = signature.digest()
    client_proof = bytearray()
    i = 0
    while i < client_key.digest_size:
        client_proof.append(client_key_digest[i] ^ signature_digest[i])
        i = i + 1

    return hexlify(client_proof)

# Write to Influx
def influxwrite(result, apiurl):
    fields = flatten(json.loads(result))

    body = [
	{
		"measurement": apiurl.split('/')[1], 
		"time": time,
		"fields": fields
	}
    ]
    logging.info(body)
    if config.getboolean('influx','useinflux'):
       ifclient = InfluxDBClient(config['influx']['ifhost'], config['influx']['ifport'])
       ifclient.switch_database(config['influx']['ifdb'])
       ifclient.write_points(body)

# Calling router API
#def getapicall(server, client, apiurl, cookies): 
#    print(apiurl)
#    url = "http://%s/api/%s" % (server,apiurl)
#    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'requestverificationtoken': get_server_token(client, server) }
#    result = client.get(url, headers=headers, cookies=cookies).text
#    print(result)
#    sleep(1)
#    if USEINFLUX: 
#    	influxwrite(result,apiurl)

# Login to router using SCRAM and fetch wanted data
def login(client, server, user, password):
    # Setup session
    setup_session(client, server)

    url = "http://%s/" % server
    response = client.get(url) 

    url = "http://%s/api/user/state-login" % server
    response = client.get(url, cookies = response.cookies)
    logging.debug(response.text)

    # Get server token
    logging.info('Getting server token')
    url = "http://%s/api/webserver/token" % server
    response = client.get(url, cookies = response.cookies)

    root = ET.fromstring(response.text)
    token = root[0].text
    logging.debug(token)


    # Collect login challenge
    url = "http://%s/api/user/challenge_login" % server
    clientnonce = generate_nonce()
    request = ET.Element('request')
    username = ET.SubElement(request, 'username')
    firstnonce = ET.SubElement(request, 'firstnonce')
    mode = ET.SubElement(request, 'mode')
    username.text = 'Admin'
    firstnonce.text = clientnonce 
    mode.text = '1'	

    print (ET.tostring(request))
    headers = {'__RequestVerificationToken': token[32:64] }
    response = client.post(url, data=ET.tostring(request), headers=headers, cookies = response.cookies)

    logging.debug(response.text)

    salt = ET.fromstring(response.text)[0].text
    servernonce = ET.fromstring(response.text)[2].text
    iterations = ET.fromstring(response.text)[4].text

    logging.debug(salt)
    logging.debug(servernonce)
    logging.debug(iterations)

 
    # Get client proof 
    clientproof = get_client_proof(
        clientnonce, servernonce, password, salt, 100).decode('UTF-8')
    logging.debug(clientproof)
    # Authenticate
    headers = {'__RequestVerificationToken': response.headers['__RequestVerificationToken']}
    url = "http://%s/api/user/authentication_login" % server
    request = ET.Element('request')
    xclientproof = ET.SubElement(request, 'clientproof')
    xfinalnonce = ET.SubElement(request, 'finalnonce')
    xclientproof.text = clientproof
    xfinalnonce.text = servernonce 

    logging.debug(ET.tostring(request))
    response = client.post(url, data=ET.tostring(request), headers=headers, cookies=response.cookies)

    logging.debug(response.text)


    logoutrequestverificationtoken = response.headers['__RequestVerificationTokenone']
    url = "http://%s/api/user/state-login" % server
    response = client.get(url)
    logging.debug(response.text)

    for sections in config['useapi']:
        print (sections)
	
        api = config[sections]['api']    
        logging.info('Getting ' + api)  
        url = "http://%s/api/%s" % (server, api)
        response = client.get(url, cookies=response.cookies)
        logging.debug(url)
        logging.debug(response.text)
 
        if (config.getboolean('useapi', sections)):
            itersource = [e.strip() for e in config.get(sections, 'sourcefields').split(',')] 
            itertarget = [e.strip() for e in config.get(sections, 'targetfields').split(',')] 
            itertypes = [e.strip() for e in config.get(sections, 'targettypes').split(',')] 
            root = ET.fromstring(response.text)
            iterresult = '{ '
            j = 0
            for iteridx, itertag in enumerate(itersource, start=0):
                for iteritem in root.iter(itertag):    
                    if j:
                       iterresult += ", "
                    if itertypes[iteridx] == 'integer':
                       logging.info(itertarget[iteridx] + ' is an integer')
                       itemtxt = int(float(re.sub("[\<\=a-zA-Z]", "", iteritem.text)))
                       iterresult += '"'+ itertarget[iteridx]+'": '+ str(itemtxt) 
                    else :
                       logging.info(itertarget[iteridx] + ' is a string')
                       itemtxt = iteritem.text
                       iterresult += '"'+ itertarget[iteridx]+'": "'+ itemtxt + '"' 
                    j = 1
            iterresult += ' }' 
            logging.debug(iterresult)
            influxwrite(iterresult, api) 


    url = "http://%s/api/user/logout" % server
    request = ET.Element('request')
    xmllogout= ET.SubElement(request, 'Logout')
    xmllogout.text='1'
    headers = {'__RequestVerificationToken': logoutrequestverificationtoken }
 
    response = client.post(url, data=ET.tostring(request), headers=headers, cookies = response.cookies)

    logging.debug(response.text)



def main():
    """ main method """

    logging.basicConfig(format='%(levelname)s:%(message)s', level=logging.DEBUG)
    
    client = requests.Session()
    login(client, config['modem']['ipaddress'], config['modem']['user'], str.encode(config['modem']['password']))



if __name__ == "__main__":
    sys.exit(main())
