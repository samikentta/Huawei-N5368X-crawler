#!/usr/bin/env python
import sys
import uuid
import hashlib
import hmac
import json
import datetime
from time import sleep
from binascii import hexlify
import requests
from influxdb import InfluxDBClient
from flatten_json import flatten 

time = datetime.datetime.utcnow()

# Settings 
ROUTER="192.168.8.1"   		# Router IP address
USER="Admin"			# Router username
PASSWORD=b"password_here"	# Router password
USEINFLUX=False		        # Whether to use Influx DB or not, set True or False 


# Setup Influx database details in case that is used
if USEINFLUX:
    ifdb = "database_name"		# Database name
    ifhost = "database_ip_address"	# Database server IP address
    ifport = "8086"			# Database portnumber, 8086 by default

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
    url = "http://%s/api/web/crsf_token" % server
    token_response = client.get(url).text
    root = json.loads(token_response)["tokens"].split(',')
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
    ifclient = InfluxDBClient(ifhost, ifport)
    ifclient.switch_database(ifdb)
    ifclient.write_points(body)

# Calling router API
def apicall(server, client, apiurl, tokeni, cookies): 
    print(apiurl)
    url = "http://%s/api/%s" % (server,apiurl)
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               'requestverificationtoken': tokeni}
    result = client.get(url, headers=headers, cookies=cookies).text
    print(result)
    sleep(1)
    if USEINFLUX: 
    	influxwrite(result,apiurl)

# Login to router using SCRAM and fetch wanted data
def login(client, server, user, password):
    # Setup session
    setup_session(client, server)

    # Get server token
    token = get_server_token(client, server)

    # Collect login challenge
    url = "http://%s/api/login/login_challenge" % server
    clientnonce = generate_nonce()
    firstnonce = clientnonce
    payload = {
	'username': user,
	'firstnonce': firstnonce
    } 
    headers = {'requestverificationtoken': token[0]}
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
    headers = {'Content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
               'requestverificationtoken': token[1]}
    url = "http://%s/api/login/login_auth" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response.cookies)

    # Update token 
    token = get_server_token(client, server)

    # Finalize login
    payload ={
	'status': '0'
    }
    headers = {'requestverificationtoken': token[0]}
    url = "http://%s/api/login/login_done" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response2.cookies)

    # Fetching data
    apicall(server, client, 'modemmng/getAntennaConfiguration', token[1], response2.cookies)
    apicall(server, client, 'modemmng/getSignal', token[2], response2.cookies)
    apicall(server, client, 'modemmng/getNrAirStat', token[3], response2.cookies)
    apicall(server, client, 'signalmng/getsiglevel', token[4], response2.cookies)
    apicall(server, client, 'web/uptime', token[5], response2.cookies)
    
    # Logout
    payload ={'status': '0'}
    headers = {'requestverificationtoken': token[6]}
    url = "http://%s/api/login/login_out" % server
    response2 = client.post(url, data=json.dumps(payload), headers=headers, cookies=response2.cookies)

def main():
    """ main method """
    client = requests.Session()
    login(client, ROUTER, USER, PASSWORD)


if __name__ == "__main__":
    sys.exit(main())
