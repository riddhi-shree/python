#!usr/bin/env python
import re
import operator
import ntpath
import os
import datetime

class ExtractVulnInfo:
	myfile = ""
	vulnblock = []
	tableOfContents = [] 
	vulnref = ""
	vulnrefs = []
	vulnerabilities = {}
	mitigation = ""
	index = 1
	lock = False
	urlLock = False
	sorted_vulnlist = []
	title = ""
	x = []
	criticalcount = 0
	highcount = 0
	mediumcount = 0
	lowcount = 0
	visitedVulnsList = []
	URL = ""

	def __init__(self, absolute_filename):
		self.filename = absolute_filename
		self.myfile = open(absolute_filename)

		
	def print2file(self, mylist, outfile):
		for item in mylist:		
			outfile.write(item)
			outfile.write("\n")
			
		outfile.write("\n")


	def getTitleWithSeverity(self, title):
		vulnlist = open(os.path.join(os.getcwd(),"vulnSeverityList.txt"))
		newtitle = ""
		for vuln in vulnlist:
			vuln = vuln.strip()
			if vuln.find(title) >0 and vuln not in self.visitedVulnsList:
				self.visitedVulnsList.append(vuln)
				severity = vuln.split("-")[0].lower().strip()

				if severity == "critical":
					self.criticalcount += 1
				elif severity == "high":
					self.highcount += 1
				elif severity == "medium":
					self.mediumcount += 1
				elif severity == "low":
					self.lowcount += 1
				else:
					vuln = "undefined-" + vuln

				newtitle = vuln
				break
		vulnlist.close()
		return newtitle


	def initialize(self):
		del self.vulnblock[:]
		self.vulnref = ""
		del self.vulnrefs[:]
		self.vulnerabilities.clear()
		self.mitigation = ""
		self.index = 1
		self.lock = False
		self.urlLock = False
		del self.sorted_vulnlist[:]
		self.title = ""
		del self.x[:]
		del self.tableOfContents[:]
		del self.visitedVulnsList[:]
		self.URL = ""

		
	def getData(self):
		self.initialize()
		for line in self.myfile:
			line = line.strip()
			if not self.lock and line.find("[!]") >0 and line.find(" Title: ") >0:
				vulntitle = re.match(r'(.*)Title: (.*?)$',line,re.M)
				title = vulntitle.group(2)
				newtitle = self.getTitleWithSeverity(title) 
				if not newtitle:
					continue
					
				self.vulnblock.append(newtitle)
				self.lock = True
				continue
			elif not self.urlLock and line.find(" URL: ") >0:
				match = re.match(r'(.*)URL: (.*?)$',line,re.M)
				self.URL = match.group(2)
				#print (self.URL)
				self.urlLock = True
				
			if self.lock and not line:
				self.vulnblock.append("Reference")
				self.vulnblock += self.vulnrefs
				self.vulnblock.append("Mitigation")
				self.vulnblock.append(self.mitigation)		
				self.vulnerabilities[self.index] = self.vulnblock
				self.vulnblock = []
				self.vulnrefs = []
				self.index += 1
				self.lock = False
			elif self.lock and line:
				if line.find("http") >0:
					vulnref = line[len("Reference: "):]
					self.vulnrefs.append(vulnref)
					
				if line.find("Fixed in: ") >0:
					self.mitigation = line[13:]
			
		self.sorted_vulnlist = sorted(self.vulnerabilities.items(), key=lambda t:t[1])

		if not os.path.exists("vuln"):
			os.makedirs("vuln")
		outfile = open(os.path.join(os.path.join(os.getcwd(),"vuln"), "vulnlist_" + ntpath.basename(self.filename)), 'a')
		outfile.write(self.URL + "\n\n")
		outfile.write("Date: " + datetime.datetime.now().strftime("%d-%B-%Y") + "\n\n")
		outfile.write("Issues Summary\n")
		outfile.write("Critical: %d; High: %d; Medium: %d; Low: %d\n\n" %(self.criticalcount, self.highcount, self.mediumcount, self.lowcount))
		outfile.write("Issues Description\n")
		
		self.index =1
		for self.x in self.sorted_vulnlist:
			self.x[1][0] = str(self.index)+"-"+self.x[1][0]
			self.tableOfContents.append(self.x[1][0])
			self.print2file (self.x[1], outfile)
			self.index += 1
		
		outfile.write("Contents\n")
		for content in self.tableOfContents:
			outfile.write(content + "\n")

		outfile.close()
		self.myfile.close()
		
"""
myObject = ExtractVulnInfo("D:\\Path\\To\\filename.txt")
myObject.getData()
"""
