#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This file is part of the Wapiti project (http://wapiti.sourceforge.net)
# Copyright (C) 2008-2014 Nicolas Surribas
#
# Original authors :
# David del Pozo
# Alberto Pastor
# Copyright (C) 2008 Informatica Gesfor
# ICT Romulus (http://www.ict-romulus.eu)
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
from xml.dom.minidom import Document
from wapitiCore.report.reportgenerator import ReportGenerator
import datetime


def isPeerAddrPort(p):
    """Is p a (str,int) tuple? I.E. an (ip_address,port)"""
    if type(p) == tuple and len(p) == 2:
        return type(p[0]) == str and type(p[1]) == int
    else:
        return False


class VulneraNetXMLReportGenerator(ReportGenerator):
    """
    This class generates a report with the method printToFile(fileName) which contains
    the information of all the vulnerabilities notified to this object through the
    method logVulnerability(category,level,url,parameter,info).
    The format of the file is XML and it has the following structure:
    <report type="security">
        <generatedBy id="Wapiti 2.3.0"/>
            <bugTypeList>
                <bugType name="SQL Injection">
                    <bugList/>

    <report>
        <vulnerabilityTypeList>
            <vulnerabilityType name="SQL Injection">
                <vulnerabilityList>
                    <vulnerability level="3">
                        <url>http://www.a.com</url>
                        <parameters>id=23</parameters>
                        <info>SQL Injection</info>
                    </vulnerability>
                </vulnerabilityList>
            </vulnerabilityType>
        </vulnerabilityTypeList>
    </report>
    """

    def __init__(self):
        self.__ts = datetime.datetime.now()
        self.__xmlDoc = Document()
        self.__vulnerabilityTypeList = None

    def setReportInfo(self, target, scope=None, date_string="", version=""):
        report = self.__xmlDoc.createElement("Report")

        report.setAttribute("generatedBy", version)
        report.setAttribute("generationDate", self.__ts.isoformat())
        self.__vulnerabilityTypeList = self.__xmlDoc.createElement("VulnerabilityTypeList")
        report.appendChild(self.__vulnerabilityTypeList)

        self.__xmlDoc.appendChild(report)

    def __addToVulnerabilityTypeList(self, vulnerabilityType):
        self.__vulnerabilityTypeList.appendChild(vulnerabilityType)

    def addVulnerabilityType(self, name, description="", solution="", references={}):
        """
        This method adds a vulnerability type, it can be invoked to include in the
        report the type.
        The types are not stored previously, they are added when the method
        logVulnerability(category,level,url,parameter,info) is invoked
        and if there is no vulnerability of a type, this type will not be presented
        in the report
        """
        vulnerability_type = self.__xmlDoc.createElement("VulnerabilityType")
        vulnerability_type.appendChild(self.__xmlDoc.createElement("VulnerabilityList"))

        vuln_title_node = self.__xmlDoc.createElement("Title")
        vuln_title_node.appendChild(self.__xmlDoc.createTextNode(name))
        vulnerability_type.appendChild(vuln_title_node)

        self.__addToVulnerabilityTypeList(vulnerability_type)
        if description != "":
            description_node = self.__xmlDoc.createElement("Description")
            description_node.appendChild(self.__xmlDoc.createCDATASection(description))
            vulnerability_type.appendChild(description_node)
        if solution != "":
            solution_node = self.__xmlDoc.createElement("Solution")
            solution_node.appendChild(self.__xmlDoc.createCDATASection(solution))
            vulnerability_type.appendChild(solution_node)
        if references != "":
            references_node = self.__xmlDoc.createElement("References")
            for ref in references:
                reference_node = self.__xmlDoc.createElement("Reference")
                name_node = self.__xmlDoc.createElement("name")
                url_node = self.__xmlDoc.createElement("url")
                name_node.appendChild(self.__xmlDoc.createTextNode(ref))
                url_node.appendChild(self.__xmlDoc.createTextNode(references[ref]))
                reference_node.appendChild(name_node)
                reference_node.appendChild(url_node)
                references_node.appendChild(reference_node)
            vulnerability_type.appendChild(references_node)
        return vulnerability_type

    def __addToVulnerabilityList(self, category, vulnerability):
        vulnerability_type = None
        for node in self.__vulnerabilityTypeList.childNodes:
            title_node = node.getElementsByTagName("Title")
            if (title_node.length >= 1 and
                title_node[0].childNodes.length == 1 and
                    title_node[0].childNodes[0].wholeText == category):
                vulnerability_type = node
                break
        if vulnerability_type is None:
            vulnerability_type = self.addVulnerabilityType(category)
        vulnerability_type.childNodes[0].appendChild(vulnerability)

    def logVulnerability(self,
                         category=None,
                         level=0,
                         request=None,
                         parameter="",
                         info=""):
        """
        Store the information about the vulnerability to be printed later.
        The method printToFile(fileName) can be used to save in a file the
        vulnerabilities notified through the current method.
        """

        peer = None

        vulnerability = self.__xmlDoc.createElement("Vulnerability")

        if level == 1:
            st_level = "Low"
        elif level == 2:
            st_level = "Moderate"
        else:
            st_level = "Important"

        level_node = self.__xmlDoc.createElement("Severity")
        level_node.appendChild(self.__xmlDoc.createTextNode(st_level))
        vulnerability.appendChild(level_node)

        ts_node = self.__xmlDoc.createElement("DetectionDate")
        #tsNode.appendChild(self.__xmlDoc.createTextNode(ts.isoformat()))
        vulnerability.appendChild(ts_node)

        ##
        url_detail_node = self.__xmlDoc.createElement("URLDetail")
        vulnerability.appendChild(url_detail_node)

        url_node = self.__xmlDoc.createElement("URL")
        url_node.appendChild(self.__xmlDoc.createTextNode(request.url))
        url_detail_node.appendChild(url_node)

        if peer is not None:
            peer_node = self.__xmlDoc.createElement("Peer")
            if isPeerAddrPort(peer):
                addr_node = self.__xmlDoc.createElement("Addr")
                addr_node.appendChild(self.__xmlDoc.createTextNode(peer[0]))
                peer_node.appendChild(addr_node)

                portNode = self.__xmlDoc.createElement("Port")
                portNode.appendChild(self.__xmlDoc.createTextNode(str(peer[1])))
                peer_node.appendChild(portNode)
            else:
                addr_node = self.__xmlDoc.createElement("Addr")
                addr_node.appendChild(self.__xmlDoc.createTextNode(str(peer)))
                peer_node.appendChild(addr_node)
            url_detail_node.appendChild(peer_node)

        parameter_node = self.__xmlDoc.createElement("Parameter")
        parameter_node.appendChild(self.__xmlDoc.createTextNode(parameter))
        url_detail_node.appendChild(parameter_node)

        ##

        info_node = self.__xmlDoc.createElement("Info")
        info = info.replace("\n", "<br />")
        info_node.appendChild(self.__xmlDoc.createTextNode(info))
        url_detail_node.appendChild(info_node)

        self.__addToVulnerabilityList(category, vulnerability)

    def generate_report(self, filename):
        """
        Create a xml file with a report of the vulnerabilities which have been logged with
        the method logVulnerability(category,level,url,parameter,info)
        """
        f = open(filename, "w")
        try:
            f.write(self.__xmlDoc.toxml(encoding="UTF-8"))
        finally:
            f.close()
