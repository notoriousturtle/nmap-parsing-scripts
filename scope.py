#!/usr/bin/python

"""
Parses nmap output to provide a list of up hosts, and IPs, for scoping purposes.
"""

import sys
import nmap
import getopt
import os

def usage():
    print("Usage: "+sys.argv[0]+" -f <filename.xml>")

if __name__ == '__main__':
    file = ""

    try:
        opts, args = getopt.getopt(sys.argv[1:], "f:")
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-f", "--file"):
            file = arg

    if len(sys.argv) > 1:
        if sys.argv[1]:
            file = sys.argv[1]

    if file == "":
        usage()
        sys.exit(2)

    if os.path.isfile(file) == False:
        print("Source file does not exist")
        sys.exit(1)

    nm = nmap.PortScanner()
    nm.analyse_nmap_xml_scan(open(file).read())

    allHosts = nm.all_hosts()
    print("All hosts up (with, and without open ports), total: "+str(len(allHosts)))
    print("Command line used: "+nm.command_line())

    real = 0
    for host in allHosts:
        if nm[host].state() == 'up':

            for proto in nm[host].all_protocols():
                sys.stdout.write(host+" ")
                sys.stdout.write("("+proto+": ")
                allPorts = nm[host][proto].keys()
                allPorts.sort()

                for port in allPorts:
                    if nm[host][proto][port]['state'] == "open":
                        sys.stdout.write(str(port)+", ")
                sys.stdout.write(")")

                real = real+1
                print("")


    print("Total hosts up, with ports (base on this number): "+str(real))
