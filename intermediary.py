#
# 			== sedirektapi ==
#		* Unofficial API for domanhanteraren.sedirekt.se *
#
# Copyright (C) 2018 Gustaf Haglund <kontakt@ghaglund.se>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
import requests, sys, json, iisapi

secret = None
username = None
passwd = None

class dotSEIntermeditary(BaseHTTPRequestHandler):
	# When the intermediary has authenticiated with .SE Direkt,
	# it's then expected that all following queries are legitimate.
	# The session is automatically terminated after 15 mins of inactivity.
	# Secure your web server (client towards the intermediary) properly!

	def __init__(self, request, client_address, server):
		self.initialized_auth = False
		BaseHTTPRequestHandler.__init__(self, request, client_address, server)

	def do_GET(self):
		code = 200
		cookie = None
		output = ''

		authtoken = self.path.split('/')[1]
		print(authtoken)
		print(secret)

		if authtoken == secret:
			# Remember this is plain HTTP and you need to be certain whether
			# your internal network is trustworthy.
			if not self.initialized_auth:
				self.initialized_auth = requests.cookies.cookiejar_from_dict(self.login())
			query = self.path.split('/')[2]
			if '_' in query:
				if query.lower() == 'login':
					# The safest bet
					sys.exit(-1)
				output = getattr(iisapi.dotSEDirekt(cookies=self.initialized_auth), query.split('_')[1])()
		else:
			# This proably only happens if the intermediary is exposed,
			# or the internal network is compromised,
			# then this is the safest bet.
			sys.exit(-1)

		if (len(output) == 0 and output != True) or output == False:
			code = 500
		else:
			# Return answer in JSON
			output = json.dumps(output)

		self.send_response(code)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		if code == 200:
			self.wfile.write(output.encode('utf-8'))

	def login(self):
		req = requests.Session()
		r = req.get('https://domanhanteraren.sedirekt.se/start/login')
		soup = BeautifulSoup(r.text, 'html.parser')
		xtoken = soup.find(type='hidden', name='input')['value']

		return req.post('https://domanhanteraren.sedirekt.se/start/login',
			data = {'xtoken':xtoken, 'username':username, 'password':passwd}).cookies.get_dict()

def create(ip):
	server_address = (ip, 8192)
	httpd = HTTPServer(server_address, dotSEIntermeditary)

	global secret
	global username
	global passwd

	# Please safeguard this file with proper ACL. chmod and the like
	with open('dotSE.details') as f:
		details = [line.rstrip() for line in f]
		secret = details[0]
		username = details[1]
		passwd = details[2]

	try:
		httpd.serve_forever()
	except KeyboardInterrupt:
		pass
	httpd.server_close()

if __name__ == "__main__":
	create('127.0.0.1')
