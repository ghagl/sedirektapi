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

from bs4 import BeautifulSoup
import requests, sys

secret = None
username = None
passwd = None

class dotSEIntermeditary(BaseHTTPRequestHandler):
	def __init__(self):
		self.api = iisapi.dotSEDirekt()

	# Once the intermediary has authenticiated with .SE Direkt,
	# it's then expected that all following queries are legitimate.
	# The session is automatically terminated after 15 mins of inactivity.
	# Secure your web server (client towards the intermediary) properly!
	def do_GET(self):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		cookie = None
		output = ''

		if self.path == secret:
			# Remember this is plain HTTP and you need to be certain whether
			# your internal network is trustworthy.
			requests.cookies.cookiejar_from_dict(self.login(), self.api.req.cookies)
		else if '_' in self.path:
			query = self.path.split('_')[1].lower()
			if query == 'login':
				# The safest bet
				sys.exit(-1)
			output = iisapi.(query)()
		else:
			# This proably only happens if the intermeditary is exposed,
			# or the internal network is compromised,
			# then this is the safest bet.
			sys.exit(-1)

		self.wfile.write(output.encode('utf-8'))

	def login(self):
		req = requests.Session()
		r = req.get('https://domanhanteraren.sedirekt.se/start/login')
		soup = BeautifulSoup(r.text, 'html.parser')
		xtoken = soup.find(type='hidden', name='input')['value']

		return req.post('https://domanhanteraren.sedirekt.se/start/login',
			data = {'xtoken':xtoken, 'username':username, 'password':password}).cookies.get_dict()

def create(ip):
	server_address = (ip, 8192)
	httpd = server_class(server_address, dotSEIntermeditary)

	# Please safeguard this file with proper ACL. chmod and the like
	with open('dotSE.details') as f:
		details = [line.rstrip() for line in f]
		secret = details[0]
		username = details[1]
		passwd = details[2]


