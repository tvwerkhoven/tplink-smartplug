#!/usr/bin/env python2
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

import socket
import argparse
from struct import pack, unpack

version = 0.4

# Check if hostname is valid
def validHostname(hostname):
	try:
		socket.gethostbyname(hostname)
	except socket.error:
		parser.error("Invalid hostname.")
	return hostname

# Predefined Smart Plug Commands
# For a full list of commands, consult tplink_commands.txt
commands = {'info'     : '{"system":{"get_sysinfo":{}}}',
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
	for plain in map(ord, string):
		key ^= plain
		result.append(key)
	return b''.join(map(chr, result))

def decrypt(string):
	key = 171
	result = []
	for cipher in map(ord, string):
		result.append(key ^ cipher)
		key = cipher
	return b''.join(map(chr, result))

# Parse commandline arguments
description="TP-Link Wi-Fi Smart Plug Client v" + str(version)
parser = argparse.ArgumentParser(description=description)
parser.add_argument("--version", action="version", version=description)

parser.add_argument("-t", "--target", metavar="<hostname>", required=True, help="Target hostname or IP address", type=validHostname)

group = parser.add_mutually_exclusive_group()
group.add_argument("-c", "--command", metavar="<command>", help="Preset command to send. Choices are: "+", ".join(commands), choices=commands)
group.add_argument("-j", "--json", metavar="<JSON string>", help="Full JSON string of command to send")

args = parser.parse_args()


# Set target IP, port and command to send
ip = args.target
port = 9999
cmd = args.json if args.json else commands[args.command or 'info']



# Send command and receive reply
try:
	sock_tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock_tcp.connect((ip, port))
	sock_tcp.send(pack('>I', len(cmd)) + encrypt(cmd))
	data = sock_tcp.recv(2048)
	dlen = 4 + unpack('>I', data[:4])[0]
	while len(data) < dlen:
		data += sock_tcp.recv(2048)
	sock_tcp.close()

	print "%-16s %s" % ("Sent(%d):" % (len(cmd),), cmd)
	print "%-16s %s" % ("Received(%d):" % (len(data),), decrypt(data[4:]))
except socket.error:
	quit("Cound not connect to host " + ip + ":" + str(port))
