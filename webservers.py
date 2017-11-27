#!/usr/bin/python

"""
Parses nmap output and opens all web servers in your default browser
"""

import sys
import nmap
import getopt
import os
import webbrowser
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

    print("--- Up web servers")

    real = 0
    for host in allHosts:
        if nm[host].state() == 'up':

            for proto in nm[host].all_protocols():
                    allPorts = nm[host][proto].keys()
                    allPorts.sort()

                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "open":
                            #product = nm[host][proto][port]['product']
                            if nm[host][proto][port]['name'] == "http":
                                #attempt to detect if should connect via https, or http
                                prefix = "http://"
                                if "443" in str(port):
                                    prefix = "https://"
                                #host could be the hostname instead: nm[host].hostname()
                                print(prefix+host+":"+str(port))
                                webbrowser.open(prefix+host+":"+str(port))

                                real = real+1
                                time.sleep(2)


    print("Total web servers up: "+str(real))
