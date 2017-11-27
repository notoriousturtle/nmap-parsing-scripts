#!/usr/bin/python

"""
Parses nmap output and runs sslscan on each SSL server
"""

import sys
import nmap
import getopt
import os
import subprocess
import time

def usage():
    print("Usage: "+sys.argv[0]+" -i <filename.xml>")
    print("       -i, xml input file")

if __name__ == '__main__':
    file = ""

    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'i:', ['input=', 
                                                         ])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in options:
        if opt in ("-i", "--input"):
            file = arg

    if file == "":
        usage()
        sys.exit(2)

    if os.path.isfile(file) == False:
        print("Source file does not exist")
        sys.exit(1)

    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(open(file).read())

    allHosts = nm.all_hosts()
    print("Command line used: "+nm.command_line())

    print("--- Testing SSL servers")

    real = 0
    for host in allHosts:
        if nm[host].state() == 'up':
            for proto in nm[host].all_protocols():
                    allPorts = nm[host][proto].keys()
                    allPorts.sort()

                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "open":
                            #product = nm[host][proto][port]['product']
                            #attempt to detect if an SSL service
                            if "443" in str(port):
                                print(" -- "+host+":"+str(port))

                                subprocess.call(["sslscan", host+":"+str(port)])

                                print("")
                                real = real+1
                                time.sleep(2)

    print("Total tested servers: "+str(real))
