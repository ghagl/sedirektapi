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

from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
import intermeditary
import requests

# * Scope of dotSEDirekt: *
# listDomains() returns a list of domains
# removeDNSSEC(domainid[please use reference given by listDomains()]) removes registrered DNSSEC keys
# probeDNSSEC(domainid[please use reference given by listDomains()]) probes for DNSSEC
# addDNSSEC(key=[please use reference given by probeDNSSEC()]) adds DNSSEC key
# log() retrieves the domain log

# Never ever use sedirektapi for directly logging in to the .SE Direkt service.
# It should be done by an intermeditary only exposed to an internal network with proper ACL.
# The consequence of a breach affecting your password for the .SE Direkt service might be that
# you lose access to your domain. Please instead use the intermediary features (e.g. connectIntermediary()).

class dotSEDirekt:
	# intermeditary: Internal network IP to intermediary (the intermediary should only be exposed to an internal network!)
	# secret: Secret for communicating with the intermediary
	def __init__(self, intermeditary, secret):
		self.intermeditary = intermeditary
		self.secret = secret
		self.req = requests.Session()
		self.initialized = False

	def connectIntermeditary(self):
		cookiereq = requests.get(self.intermeditary+'/{0}'.format(self.secret))
		# OK: we should have got the cookie. We have now access to .SE Direkt.
		requests.cookies.cookiejar_from_dict(json.loads(cookiereq.text), self.req.cookies)

	def query(self, query):
		return json.loads(requests.get(self.intermeditary+'/{0}'.format(query).text)

	def listDomains(self):
		list = self.req.get('https://domanhanteraren.sedirekt.se/domains')
		domains = BeautifulSoup(list.text, 'html.parser')
		thelist = {}
		for elem in domains.find_all('tbody'):
			for link in elem.find_all('a'):
				thelist[link.string] = link.get('href').split('=')[1]})
		return thelist

	def removeDNSSEC(self, domainid):
		pass

	# Internal use only: retrieves xtoken from a page
	def getXtoken(self, page):
		page = self.req.get(page)
		parse = BeautifulSoup(page.text, 'html.parser')
		xtoken = soup.find(type='hidden', name='input')
		if len(xtoken) > 0:
			xtoken = xtoken[0]['value']
		else:
			xtoken = xtoken['value']
		return xtoken

	def probeDNSSEC(self, domainid):
		page = 'https://domanhanteraren.sedirekt.se/domains/details/dnssec?id={0}'.format(domainid)
		xtoken = self.getXtoken(page)
		dnssec = self.req.post(page, data = {'xtoken':xtoken, 'updatenskeylist':'Hämta-nycklar-från-namnservrar'})
		parser = BeautifulSoup(dnssec.text, 'html.parser')
		list = []
		forms = parser.find_all('form')
		for key in forms[1].find_all('tr'):
			if key.th != None and key.th.get('class') != None:
				continue
			if key.ul != None:
				break
			data = key.find_all('td')
			list.append({'dnskey' : data[0].input.get('value'), 'status': data[1].string,
						'keytag' : data[2].string, 'algorithm' : data[3].string, 'fingerprint' : data[4].input.get('value'),
						'keytype' : data[5].string})
		return list

	def removeDNSSEC(self, domainid):
		page = 'https://domanhanteraren.sedirekt.se/domains/details/dnssec?id={0}'.format(domainid)
		xtoken = self.getXtoken(page)
		self.req.post(page, data = {'xtoken':xtoken, upddnskeys: 'Ta+bort+alla+publicerade+nycklar'})

	def addDNSSEC(self, domainid, dnskey):
		page = 'https://domanhanteraren.sedirekt.se/domains/details/dnssec?id={0}'.format(domainid)
		xtoken = self.getXtoken(page)
		self.req.post(page, data = {'xtoken':xtoken, dnskey:dnskey, upddnskeys: 'Publicera+ikryssade+nycklar'})

	def log(self, domainid, page = 1):
		page = self.req.get('https://domanhanteraren.sedirekt.se/domains/details/history?id={0}&page={1}'.format(domainid, page))
		parser = BeautifulSoup(page.text, 'html.parser')
		list = []
		tbody = parser.find('tbody')
		for tr in tbody.find_all('tr'):
			if tr.th != None:
				continue
			tds = tr.find_all('td')
			list.append({'type': tds[0].string, 'action':tds[1].string, 'object':tds[2].string, 'date':tds[3].string})
		return list

	def initAPI(self):
		if self.initialized == True:
			return
		self.connectIntermeditary()
		self.initialized = True
