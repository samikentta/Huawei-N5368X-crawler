#!/usr/bin/env python

# Support for legacy firmware

import sys
import uuid
import hashlib
import hmac
import json
import datetime

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

token = []
time = datetime.datetime.utcnow()

# Settings 
ROUTER="192.168.1.1"   		# Router IP address
USER="Admin"			# Router username
PASSWORD=b"password_here"	# Router password
USEINFLUX=True			# Whether to use Influx DB or not, set True or False 


# Setup Influx database details in case that is used
if USEINFLUX:
    ifdb = "huawei"
    ifhost = "192.168.8.202"
    ifport = "8086"

# Generate clientside nonce
def generate_nonce():
    return uuid.uuid4().hex + uuid.uuid4().hex

# Get session cookie
def setup_session(client, server):
    url = "http://%s/" % server
    response = client.get(url)
    response.raise_for_status()
    sleep(1)

# Get server token
def get_server_token(client, server):
    global token
    token.pop(0)
    if len(token)<1:
    	url = "http://%s/api/web/crsf_token" % server
    	token_response = client.get(url).text
    	token = json.loads(token_response)["tokens"].split(',')
    return token[0] 

def get_pubkey(client, server, cookies):
    url = "http://%s/api/web/pubkey" % server
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8','requestverificationtoken': get_server_token(client, server) } 
    pubkey_response = client.get(url, headers=headers, cookies=cookies).text
    root = json.loads(pubkey_response)["pubkey"]
    return root

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
    print(body)
    ifclient = InfluxDBClient(ifhost, ifport)
    ifclient.switch_database(ifdb)
    ifclient.write_points(body)

# Calling router API
def getapicall(server, client, apiurl, cookies): 
    print(apiurl)
    url = "http://%s/api/%s" % (server,apiurl)
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'requestverificationtoken': get_server_token(client, server) }
    result = client.get(url, headers=headers, cookies=cookies).text
    print(result)
    sleep(1)
    if USEINFLUX: 
    	influxwrite(result,apiurl)

def postpayload(apiurl):
    if apiurl == 'modemmng/queryModemMonitorWithName':
    	payload = {
    		'monitorName': 'dataFlow',
    		'argJson': { }
    	}
    elif apiurl == 'modemmng/queryModemIMSI':
        payload = {
                'monitorName': 'protocolStatus',
                'argJson': { 'cmd': 'IMSI' }
        }

    elif apiurl == 'modemmng/queryModemIMEI':
        payload = {
                'monitorName': 'protocolStatus',
                'argJson': { 'cmd': 'IMEI'}
        }
    elif apiurl == 'equipservice/getequippara':
        payload = {
                'ParaName': 'SNEX'
        }
 
    return payload

# POST to router API
def postapicall(server, client, apiurl, cookies):
    pubkey = get_pubkey(client, server, cookies)
    # print(pubkey)

    payloadstr = json.dumps(postpayload(apiurl)).encode('utf8')
    key = RSA.import_key(pubkey)
    encryptor = PKCS1_OAEP.new(key)
    encrypted = encryptor.encrypt(payloadstr)

    base64_bytes = base64.b64encode(encrypted)
    base64_message = base64_bytes.decode('utf-8')

    headers = {'requestverificationtoken': get_server_token(client, server) }
    url = "http://%s/api/%s" % (server,apiurl)
    result = client.post(url, data=base64_message, headers=headers, cookies=cookies).text
    if USEINFLUX:
        influxwrite(result, apiurl)
    print(result)


# Login to router using SCRAM and fetch wanted data
def login(client, server, user, password):
    # Setup session
    setup_session(client, server)
    global token
    token.append("INITIALIZE")


    # Get server token

    # Collect login challenge
    url = "http://%s/api/login/login_challenge" % server
    clientnonce = generate_nonce()
    firstnonce = clientnonce
    payload = {
	'username': user,
	'firstnonce': firstnonce
    } 
    headers = {'requestverificationtoken': get_server_token(client, server) }
    response = client.post(url, data=json.dumps(payload), headers=headers)
    servernonce = json.loads(response.text)["servernonce"]
    salt = json.loads(response.text)["salt"]
    iterations = json.loads(response.text)["iterations"]
 
    # Get client proof 
    clientproof = get_client_proof(
        clientnonce, servernonce, password, salt, iterations).decode('UTF-8')

    # Authenticate
    payload = {
	'clientproof':clientproof,
	'finalnonce':servernonce
    }
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8', 'requestverificationtoken': get_server_token(client, server)}
    url = "http://%s/api/login/login_auth" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response.cookies)

    # Update token 

    # Finalize login
    payload ={
	'status': '0'
    }
    headers = {'requestverificationtoken': get_server_token(client, server) }
    url = "http://%s/api/login/login_done" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response2.cookies)

    # Reset tokens
    del token
    token = []
    token.append("INITIALIZE")

    # Fetching data
    getapicall(server, client, 'modemmng/getAntennaConfiguration', response2.cookies)
    getapicall(server, client, 'modemmng/getSignal', response2.cookies)
    getapicall(server, client, 'modemmng/getNrAirStat', response2.cookies)
    getapicall(server, client, 'signalmng/getsiglevel', response2.cookies)
    getapicall(server, client, 'web/uptime', response2.cookies)
    getapicall(server, client, 'device/version', response2.cookies)
    
    postapicall(server, client, 'modemmng/queryModemMonitorWithName', response2.cookies)
    postapicall(server, client, 'modemmng/queryModemIMEI', response2.cookies)
    postapicall(server, client, 'modemmng/queryModemIMSI', response2.cookies)
    postapicall(server, client, 'equipservice/getequippara', response2.cookies)
 
    # Logout
    payload ={'status': '0'}
    headers = {'requestverificationtoken': get_server_token(client, server) }
    url = "http://%s/api/login/login_out" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response2.cookies)

def main():
    """ main method """
    client = requests.Session()
    login(client, ROUTER, USER, PASSWORD)


if __name__ == "__main__":
    sys.exit(main())
