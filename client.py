# -*- coding: utf-8 -*-
#
# 			== sedirektapi ==
#	* Unofficial API for domanhanteraren.sedirekt.se *
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

import requests

class iisapiClient:
	# intermeditary: Internal network IP to intermediary (the intermediary should only be exposed to an internal network!)
	# secret: Secret for communicating with the intermediary
	def __init__(self, intermediary, secret):
		self.intermediary = intermediary
		self.secret = secret

	def connectIntermediary(self, query):
		return requests.get('{0}{1}/{2}/{3}'.format('http://', self.intermediary, self.secret, '_'+query)).text

if __name__ == "__main__":
	# Change accordingly to the dotSE.details file. Don't host on localhost/127.0.0.1.
	client = iisapiClient('127.0.0.1:8192', 'default')
	print(client.connectIntermediary('listDomains'))
	print(client.connectIntermediary('probeDNSSEC'))
