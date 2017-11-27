#!/usr/bin/python

"""
Parses nmap output and performs tests on SMTP
Performs:
    * smtp-open-relay
    * smtp-enum-users
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
    nmSMTP = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(open(file).read())

    allHosts = nm.all_hosts()
    print("Command line used in scan: "+nm.command_line())

    print("--- Up SMTP servers")

    real = 0
    for host in allHosts:
        if nm[host].state() == 'up':
            for proto in nm[host].all_protocols():
                    allPorts = nm[host][proto].keys()
                    allPorts.sort()

                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "open":
                            if nm[host][proto][port]['name'] == "smtp":
                                print(host+":"+str(port))
                                nmSMTP.scan(hosts=host, arguments="-p"+str(port)+" --script smtp-open-relay -Pn")
                                if 'script' in nmSMTP[host][proto][port]:
                                    print("smtp-open-relay: "+nmSMTP[host][proto][port]['script']['smtp-open-relay'])
                                else:
                                    print("smtp-open-replay: No script output found")
                                
                                nmSMTP.scan(hosts=host, arguments="-p"+str(port)+" --script smtp-enum-users -Pn")
                                if 'script' in nmSMTP[host][proto][port]:
                                    print("smtp-enum-users: "+nmSMTP[host][proto][port]['script']['smtp-enum-users'])
                                else:
                                    print("smtp-enum-users: No script output found")                           

                                print("")

                                real = real+1
                                time.sleep(2)

    print("Total SMTP servers up, and tested: "+str(real))
