#!usr/bin/env python

import queue
import threading
import subprocess

class WorkerThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
        
    def run(self):
        while True:
            cmd = self.queue.get()
            print("Running: %s" %cmd)
            subprocess.call(cmd, shell=True)
            self.queue.task_done()
        
def main():
    cmdlist = open("D:\\2017\\Work\\ProwarenessScans\\ToVikram\\Nov2017\\wp-scan\\script\\wpscan_enumerate.bat")
    q = queue.Queue(maxsize = 14)
    for cmd in cmdlist:
        q.put(cmd)
    
    for i in range(14):
        t = WorkerThread(q)
        t.setDaemon(True)
        t.start()
    
    q.join()
        
main()