#!/usr/bin/env python3
#
# TP-Link Wi-Fi Smart Plug Protocol Client
# For use with TP-Link HS-100 or HS-110
#
# by Lubomir Stroetmann
# Copyright 2016 softScheck GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import print_function
import socket
from struct import pack, unpack
import logging
import logging.handlers

VERSION = 0.9


# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
COMMANDS = {
	'info'     : '{"system":{"get_sysinfo":{}}}',
	'on'       : '{"system":{"set_relay_state":{"state":1}}}',
	'off'      : '{"system":{"set_relay_state":{"state":0}}}',
	'ledoff'   : '{"system":{"set_led_off":{"off":1}}}',
	'ledon'    : '{"system":{"set_led_off":{"off":0}}}',
	'cloudinfo': '{"cnCloud":{"get_info":{}}}',
	'wlanscan' : '{"netif":{"get_scaninfo":{"refresh":0}}}',
	'time'     : '{"time":{"get_time":{}}}',
	'schedule' : '{"schedule":{"get_rules":{}}}',
	'countdown': '{"count_down":{"get_rules":{}}}',
	'antitheft': '{"anti_theft":{"get_rules":{}}}',
	'reboot'   : '{"system":{"reboot":{"delay":1}}}',
	'reset'    : '{"system":{"reset":{"delay":1}}}',
	'energy'   : '{"emeter":{"get_realtime":{}}}'
}


# Encryption and Decryption of TP-Link Smart Home Protocol
# XOR Autokey Cipher with starting key = 171
def encrypt(string):
	key = 171
	result = []
	chars = isinstance(string[0], str)
	if chars:
		string = map(ord, string)
	for plain in string:
		key ^= plain
		result.append(key)
	return b''.join(map(chr, result)) if chars else bytes(result)

def decrypt(string):
	key = 171
	result = []
	chars = isinstance(string[0], str)
	if chars:
		string = map(ord, string)
	for cipher in string:
		result.append(key ^ cipher)
		key = cipher
	return b''.join(map(chr, result)) if chars else bytes(result)

class CommFailure(Exception):
	pass

# Send command and receive reply
def comm(ip, cmd, port=9999):
	dec = isinstance(cmd, str)
	if dec:
		cmd = cmd.encode()
	try:
		sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock_tcp.connect((ip, port))
		sock_tcp.send(pack('>I', len(cmd)) + encrypt(cmd))
		data = sock_tcp.recv(2048)
		dlen = 4 + unpack('>I', data[:4])[0]
		while len(data) < dlen:
			data += sock_tcp.recv(2048)
		sock_tcp.close()
	except socket.error:
		raise CommFailure("Could not connect to host %s:%d" % (ip, port))
	finally:
		sock_tcp.close()
	res = decrypt(data[4:])
	return res.decode() if dec else res

if __name__ == '__main__':
	import argparse
	import sys

	# Check if hostname is valid
	def validHostname(hostname):
		try:
			socket.gethostbyname(hostname)
		except socket.error:
			parser.error("Invalid hostname.")
		return hostname

	# Init logger, defaults to console
	my_logger = logging.getLogger("MyLogger")
	my_logger.setLevel(logging.DEBUG)

	# create syslog handler which also shows filename in log
	handler_syslog = logging.handlers.SysLogHandler(address = '/dev/log')
	formatter = logging.Formatter('%(filename)s: %(message)s')
	handler_syslog.setFormatter(formatter)
	handler_syslog.setLevel(logging.INFO)
	my_logger.addHandler(handler_syslog)


	# Parse commandline arguments
	description="TP-Link Wi-Fi Smart Plug Client v%s" % (VERSION,)
	parser = argparse.ArgumentParser(description=description)
	parser.add_argument("--version", action="version", version=description)
	parser.add_argument("-n", "--naked-json", action='store_true',
		help="Output only the JSON result")

	parser.add_argument("-t", "--target", metavar="<hostname>", required=True,
		type=validHostname, help="Target hostname or IP address")

	group = parser.add_mutually_exclusive_group()
	group.add_argument("-c", "--command", metavar="<command>", choices=COMMANDS,
		help="Preset command to send. Choices are: "+", ".join(COMMANDS))
	group.add_argument("-j", "--json", metavar="<JSON string>",
		help="Full JSON string of command to send")

	parser.add_argument('--influxdb', type=str, metavar=("URI", "database"),
		default=None, nargs=2, help='If command is "energy", push to \
		influxdb. URI should point to influxdb, e.g. \
		[http/https]://<ip>:<port>. Database: e.g. smarthome.')
	parser.add_argument('--influxdb_query', type=str, metavar="query", 
		default=None, nargs="*", help='influxdb query to store data, \
		{power} (in W, as float) and {energy} (in J, as int) are available \
		variables, e.g. \'home,type=elec,device=hs110-1 energy={energy},power={power}\
		 epoch\'. Multiple arguments will be concatenated as multiple lines \
		 which allows to insert multiple entries in influxdb in one call.')

	args = parser.parse_args()

	# command to send
	cmd = args.json if args.json else COMMANDS[args.command or 'info']
	reply = ''

	try:
		reply = comm(args.target, cmd)
		ec = len(reply) <= 0
	except CommFailure as e:
		print("<<%s>>" % (str(e),), file=stderr)
		ec = 2
	finally:
		if args.naked_json:
			print(reply)
		else:
			print("%-16s %s" % ("Sent(%d):" % (len(cmd),), cmd))
			print("%-16s %s" % ("Received(%d):" % (len(reply),), reply))
	
	if (args.command == "energy") and (args.influxdb != None) and (args.influxdb_query != None):
		import requests
		import json

		# Get total_wh and power_mw from json response
		energy_wh = json.loads(reply)['emeter']['get_realtime']['total_wh']
		energy_joule = int(energy_wh)*3600

		power_mW = json.loads(reply)['emeter']['get_realtime']['power_mw']
		power_W = float(power_mW)/1000.0

		# Build URI and query
		# Something like req_url = "http://localhost:8086/write?db=smarthometest&precision=s"
		req_url = "{URI}/write?db={db}&precision=s".format(URI=args.influxdb[0],db=args.influxdb[1])
		# Something like post_data = "stats,type=usage,device=sensus power={power},energy={energy}"
		post_data = "\n".join([s.format(energy=energy_joule, power=power_W) for s in args.influxdb_query])
		
		# Post data to influxdb
		try:
			httpresponse = requests.post(req_url, data=post_data, verify=False, timeout=5)
			if (httpresponse.status_code != 204):
				my_logger.error("Push to influxdb failed: {} - {}".format(str(httpresponse.status_code), str(httpresponse.text)))

		except requests.exceptions.Timeout as e:
			my_logger.exception("Update failed due to timeout. Is influxdb running?")
	
	sys.exit(ec)
