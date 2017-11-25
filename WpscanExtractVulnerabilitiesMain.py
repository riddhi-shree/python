#!usr/bin/env python

import os, sys
import queue
import threading
import subprocess
import WpscanExtractVulnerabilities
      
def main():
    targetfolder = os.path.join(os.getcwd(),"raw/Final/")
    for root, dirs, files in os.walk(targetfolder):
        #q = queue.Queue(maxsize = len(files))
        for file in files:
            fname, fextension = os.path.splitext(file)
            if fextension == ".txt":
                myObject = WpscanExtractVulnerabilities.ExtractVulnInfo(os.path.join(targetfolder,file))
                myObject.getData()
                
        break
                
    print("Check output in following location: " + os.path.join(os.getcwd(), "vuln"))
    
main()
