#!/usr/bin/env python

# Copyright (C) 2003-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.


import base64
from binascii import hexlify
import getpass
import os
import select
import socket
import sys
import time
import traceback
from paramiko.py3compat import input

import paramiko

def agent_auth(transport, username):
    """
    Attempt to authenticate to the given transport using any of the private
    keys available from an SSH agent.
    """
    
    agent = paramiko.Agent()
    agent_keys = agent.get_keys()
    if len(agent_keys) == 0:
        return
        
    for key in agent_keys:
        print('Trying ssh-agent key %s' % hexlify(key.get_fingerprint()))
        try:
            transport.auth_publickey(username, key)
            print('... success!')
            return
        except paramiko.SSHException:
            print('... nope.')

def deploy_host(hostname, keys_to_deploy):
	username = ''
	if hostname.find('@') >= 0:
		username, hostname = hostname.split('@')
	if len(hostname) == 0:
		print('*** Hostname required.')
		return 1
	port = 22
	if hostname.find(':') >= 0:
		hostname, portstr = hostname.split(':')
		port = int(portstr)

	if len(username) == 0:
		print('*** Username required ***')
		return 1
	# now connect
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		sock.connect((hostname, port))
	except Exception as e:
		print('*** Connect failed: ' + str(e))
		traceback.print_exc()
		return 1

	try:
		t = paramiko.Transport(sock)
		try:
			t.start_client()
		except paramiko.SSHException:
			print('*** SSH negotiation failed.')
			return 1

		try:
			keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
		except IOError:
			try:
				keys = paramiko.util.load_host_keys(os.path.expanduser('~/ssh/known_hosts'))
			except IOError:
				print('*** Unable to open host keys file')
				keys = {}

		# check server's host key -- this is important.
		key = t.get_remote_server_key()
		if hostname not in keys:
			print('*** WARNING: Unknown host key!')
		elif key.get_name() not in keys[hostname]:
			print('*** WARNING: Unknown host key!')
		elif keys[hostname][key.get_name()] != key:
			print('*** WARNING: Host key has changed!!!')
			return 1
		else:
			print('*** Host key OK.')

		agent_auth(t, username)
		if not t.is_authenticated():
			print('*** Authentication failed. :(')
			t.close()
			return 1

		sftp = paramiko.SFTPClient.from_transport(t)

		dirlist = sftp.listdir('.ssh')
		keylist = []
		with sftp.open('.ssh/authorized_keys', 'r') as f:
			# Inside mode we keep track of whether were inside the managed block.
			# All lines outside the managed block are persisted.
			mode = 0
			for line in f:
				if line.startswith('# >>>'):
					mode=1
				if (mode == 1) and (line.startswith('# <<<')):
					mode=2
				if mode == 0:
					# Outside managed block, so persist.
					keylist.append(line)
				if mode == 2:
					mode=0

		keylist += ['# >>> Warning! Don\'t change this block!!!']
		keylist += keys_to_deploy
		keylist += ['# <<< End of list']
		
		f = sftp.open('.ssh/authorized_keys', 'w')
		for key in keylist:
			# Add all lines to the file. Ensure no duplicate line endings.
			f.write(key.rstrip() + '\n')

		t.close()

	except Exception as e:
		print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
		traceback.print_exc()
		try:
			t.close()
		except:
			pass
		return 1

def deploy(directory):
	# Deploy all host
	filenames = next(os.walk(directory))[2]
	import re
	# Only match absolute paths ending in a valid hostname.
	host_match = re.compile('[a-z]*@([\w]*(\.)?)*(:[1-9]{1,5})?')
	valid_keyfiles = []
	for filename in filenames:
		if host_match.match(filename):
			valid_keyfiles.append(filename)
	for keyfile in valid_keyfiles:
		keys = []
		with open(directory + '/' + keyfile, "r") as text:
			for line in text:
				keys.append(line)
		print('Deploying to {0}: {1}' . format(keyfile, keys))
		deploy_host(keyfile, keys)
# setup logging
paramiko.util.log_to_file('demo.log')
# deploy_host('vagrant@192.168.1.4', ['key 1', 'key 3'])
deploy('/tmp/deploy')

