#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2009-2014 Nicolas Surribas
#
# Original authors :
# Anthony DUBOCAGE
# Guillaume TRANCHANT
# Gregory FONTAINE
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
from wapitiCore.attack.attack import Attack
from wapitiCore.language.vulnerability import Vulnerability
import socket
import os
from wapitiCore.net import HTTP

from pyquery import PyQuery as pq
import json
import requests
import re

class switch(object):
    def __init__(self, value):
        self.value = value
        self.fall = False
 
    def __iter__(self):
        """Return the match method once, then stop"""
        yield self.match
        raise StopIteration
     
    def match(self, *args):
        """Indicate whether or not to enter a case suite"""
        if self.fall or not args:
            return True
        elif self.value in args:
            self.fall = True
            return True
        else:
            return False

class mod_fingerprint(Attack):
    """
    This class implements a "fingerprint forensic"
    """

    payloads = []
    CONFIG_FILE = "fingerprint.txt"

    name = "fingerprint"

    doGET = False
    doPOST = False

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        #self.payloads = self.loadPayloads(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE))
        self.fd = open(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE), "r+")
        self.payloads = json.load(self.fd)

    @staticmethod
    def __returnErrorByCode(code):
        err = ""
        code = int(code)
        if code == 404:
            err = "Not found"

        if code == (301 or 302):
            err = "Moved"

        if code == 200:
            err = "ok"

        return err

    @staticmethod
    def __findStringForTranslation(text): # wait to internalization
        return _(text)

    def attackGET(self, http_res):

        dir_name = http_res.dir_name
        headers = http_res.headers

        for payload in self.payloads:
            if self.verbose == 2:
                print(u"+ {0} detecting...".format(payload['title']))
            for rule in payload['rules']:
                for case in switch(rule['type']):
                    if self.verbose == 2:
                        print(u"  type: {0}".format(rule['type']))
                    if case(1):
                        url = dir_name
                        if self.verbose == 2:
                            print(u"  name: {0}".format(rule['name']))
                            print(u"  url: {0}".format(url))
                            print(u"  matching pattern: {0}".format(rule['match']))
                            print("")
                        try:
                            #data = requests.get(url, allow_redirects=True)
                            evil_req = HTTP.HTTPResource(url)

                            resp = self.HTTP.send(evil_req)
                            data, code = resp.getPageCode()

                            err = self.__returnErrorByCode(code)
                            if err == "ok":
                                d = pq(data)
                                for element in d(''.join([rule['name'], "[", rule['attributes'], "]"])).items():
                                    if re.search(rule['match'].lower(), element.attr(rule['attributes']).lower()) is not None:
                                        self.logR(_("Found fingerprint !"))
                                        self.logR(u"    -> {0}".format(evil_req.url))
                                        self.logR("Framework: {0} !".format(payload['title'])) # wait to internalization
                                        self.logVuln(category=Vulnerability.FINGERPRINT,
                                                     level=Vulnerability.LOW_LEVEL,
                                                     request=evil_req,
                                                     info=_("Framework {0} used in {1}").format(payload['title'], dir_name))
                                        self.fingerprint_flag = True
                                        #err = self.__findPatternInResponse(d.text())
                                        return
                            elif err == "Moved":
                                self.logR("This site might be moved to \"{0}\". Try again.".format(requests.get(url, allow_redirects=True).url))
                                self.fingerprint_flag = True
                                return
                        except socket.timeout:
                            break
                        break
                    if case(3):
                        if rule['name'] == "URL":
                            url = dir_name + rule['attributes']
                            if self.verbose == 2:
                                print(u"  name: {0}".format(rule['name']))
                                print(u"  url: {0}".format(url))
                                print(u"  matching pattern: {0}".format(rule['match']))
                                print("")
                            try:
                                evil_req = HTTP.HTTPResource(url)

                                resp = self.HTTP.send(evil_req)
                                data, code = resp.getPageCode()

                                err = self.__returnErrorByCode(code)
                                if err == "ok":
                                    d = pq(data)
                                    if rule['match'] in d.text():
                                        self.logR(_("Found fingerprint !"))
                                        self.logR(u"    -> {0}".format(evil_req.url))
                                        self.logR("Framework: {0} !".format(payload['title'])) # wait to internalization
                                        self.logVuln(category=Vulnerability.FINGERPRINT,
                                                     level=Vulnerability.LOW_LEVEL,
                                                     request=evil_req,
                                                     info=_("Framework {0} used in {1}").format(payload['title'], dir_name))
                                        self.fingerprint_flag = True
                                        #err = self.__findPatternInResponse(d.text())
                                        return
                            except socket.timeout:
                                break
                        else:
                            url = dir_name
                            if self.verbose == 2:
                                print(u"  name: {0}".format(rule['name']))
                                print(u"  url: {0}".format(url))                             
                                print(u"  matching pattern: {0} in html tag '{1}'".format(rule['match'], rule['name']))
                                print("")
                            try:
                                #data = requests.get(url, allow_redirects=True)
                                evil_req = HTTP.HTTPResource(url)

                                resp = self.HTTP.send(evil_req)
                                data, code = resp.getPageCode()

                                err = self.__returnErrorByCode(code)
                                if err == "ok":
                                    d = pq(data)
                                    if re.search(rule['match'], d(rule['name']).text()) is not None:
                                        self.logR(_("Found fingerprint !"))
                                        self.logR(u"    -> {0}".format(evil_req.url))
                                        self.logR("Framework: {0} !".format(payload['title'])) # wait to internalization
                                        self.logVuln(category=Vulnerability.FINGERPRINT,
                                                     level=Vulnerability.LOW_LEVEL,
                                                     request=evil_req,
                                                     info=_("Framework {0} used in {1}").format(payload['title'], dir_name))
                                        self.fingerprint_flag = True
                                        #err = self.__findPatternInResponse(d.text())
                                        return
                                elif err == "Moved":
                                    self.logR("This site might be moved to \"{0}\". Try again.".format(requests.get(url, allow_redirects=True).url))
                                    self.fingerprint_flag = True
                                    return
                            except socket.timeout:
                                break
                        break
                    if case(8):
                        break