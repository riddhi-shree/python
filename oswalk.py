#!/usr/bin/python
import os, sys

def traverse(root_dir, count):
	for root, dirs, files in os.walk(root_dir):
		print "----"*count + os.path.basename(root)
		for dir in dirs:
			traverse(os.path.join(os.path.abspath(root), dir), count+1)
		for file in files:
			print "----"*count + "----" + file
		break

traverse(sys.argv[1], 0)
#traverse(os.getcwd(), 0)
