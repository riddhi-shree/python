#!usr/bin/env python
import re
import operator
import ntpath

class ExtractVulnInfo:
	myfile = ""
	vulnblock = []
	vulnrefs = []
	vulnerabilities = {}
	index = 1
	lock = False

	def __init__(self, absolute_filename):
		self.filename = absolute_filename
		self.myfile = open(absolute_filename)
		
	def print2file(self, mylist, filename):
		outfile = open(filename, 'a')
		for item in mylist:
			#print(item)
			#Print to file			
			outfile.write(item)
			outfile.write("\n")
			
		outfile.write("\n")

	def getSeverity(self, title):
		vulnlist = open("D:\\Path\\To\\vulnSeverityList.txt")
		for vuln in vulnlist:
			if vuln.find(title) >0:
				return vuln.strip()
		
	def getData(self):
		for line in self.myfile:
			line = line.strip()
			if not self.lock and line.find("[!]") >0 and line.find(" Title: ") >0:
				vulntitle = re.match(r'(.*)Title: (.*?)$',line,re.M)
				title = vulntitle.group(2)
				newtitle = self.getSeverity(title) 
				title = title if not newtitle else newtitle
				self.vulnblock.append(title)
				self.lock = True
				continue
				
			if self.lock and not line:
				self.vulnblock.append("Reference")
				self.vulnblock += self.vulnrefs
				self.vulnblock.append("Mitigation")
				self.vulnblock.append(mitigation)		
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
					mitigation = line[13:]
			
		sorted_vulnlist = sorted(self.vulnerabilities.items(), key=lambda t:t[1])	

		self.index =1
		for x in sorted_vulnlist:
			x[1][0] = str(self.index)+"-"+x[1][0]
			self.print2file (x[1], "vulnlist_" + ntpath.basename(self.filename))
			self.index += 1
		
	
myObject = ExtractVulnInfo("D:\\Path\\To\\wpscanOutputFile.txt")
myObject.getData()
