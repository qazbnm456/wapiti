#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
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
import requests

from progressbar import AnimatedMarker, Bar, BouncingBar, Counter, ETA, \
    FileTransferSpeed, FormatLabel, Percentage, \
    ProgressBar, ReverseBar, RotatingMarker, \
    SimpleProgress, Timer, AdaptiveETA, AdaptiveTransferSpeed

class mod_buster(Attack):
    """
    This class implements a file and directory buster"
    """

    payloads = []

    name = "buster"
    CONFIG_FILE = ""
    pbar = ""

    doGET = False
    doPOST = False

    def __init__(self, http, xmlRepGenerator):
        Attack.__init__(self, http, xmlRepGenerator)

        self.known_dirs = []
        self.known_pages = []
        self.new_resources = []

    def test_directory(self, path):
        if self.verbose == 2:
            print(u"+ Testing directory {0}".format(path))
        test_page = HTTP.HTTPResource(path + "does_n0t_exist.htm")
        try:
            resp = self.HTTP.send(test_page)
            if resp.getCode() not in ["403", "404"]:
                # we don't want to deal with this at the moment
                return
            for i, candidate in enumerate(self.payloads):
                self.pbar.update(i + 1)
                url = path + candidate
                if url not in self.known_dirs and url not in self.known_pages and url not in self.new_resources:
                    page = HTTP.HTTPResource(path + candidate)
                    try:
                        resp = self.HTTP.send(page)
                        if resp.getCode() == "301":
                            loc = resp.getLocation()
                            if loc in self.known_dirs or loc in self.known_pages:
                                continue
                            self.logR("Found webpage {0}", loc)
                            self.new_resources.append(loc)
                        elif resp.getCode() not in ["403", "404"]:
                            self.logR("Found webpage {0}", page.path)
                            self.new_resources.append(page.path)
                    except requests.exceptions.Timeout:
                        continue

        except requests.exceptions.Timeout:
            pass

    def attack(self, urls, forms):
        #Load ProgressBar
        widgets = [
            Percentage(),
            ' ', Bar(),
            ' ', ETA(),
            ' ', AdaptiveETA(),
            ' ', AdaptiveTransferSpeed(),
        ]
        # Load config file...
        user_input = raw_input("[*] Use [E]lite, [G]reat or [N]ormal buster payload?\n")
        if user_input == "E":
            self.CONFIG_FILE = "busterElitePayloads.txt"
            self.pbar = ProgressBar(widgets=widgets, maxval=1292)
        elif user_input == "G":
            self.CONFIG_FILE = "busterGreatPayloads.txt"
            self.pbar = ProgressBar(widgets=widgets, maxval=7372)
        else:
            self.CONFIG_FILE = "busterPayloads.txt"
            self.pbar = ProgressBar(widgets=widgets, maxval=45524)
        self.payloads = self.loadPayloads(os.path.join(self.CONFIG_DIR, self.CONFIG_FILE))
        
        # First we make a list of uniq webdirs and webpages without parameters
        for res in urls:
            path = res.path
            if path.endswith("/"):
                if path not in self.known_dirs:
                    self.known_dirs.append(path)
            else:
                if path not in self.known_pages:
                    self.known_pages.append(path)

        # Then for each known webdirs we look for unknown webpages inside
        for current_dir in self.known_dirs:
            self.test_directory(current_dir)

        # Finally, for each discovered webdirs we look for more webpages
        while self.new_resources:
            current_res = self.new_resources.pop(0)
            if current_res.endswith("/"):
                # Mark as known then explore
                self.known_dirs.append(current_res)
                self.test_directory(current_res)
            else:
                self.known_pages.append(current_res)
        self.pbar.finish()
