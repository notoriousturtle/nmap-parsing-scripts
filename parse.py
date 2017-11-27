#!/usr/bin/python

"""
Parses nmap output to provide a list of up hosts, and IPs, for scoping purposes.
"""

import sys
import nmap
import getopt
import os

def usage():
    print("Usage: "+sys.argv[0]+" -i <filename.xml>")
    print("       -i, xml input file")
    print("       -f, filter by port number")

if __name__ == '__main__':
    file = ""
    filter = None

    try:
        options, remainder = getopt.getopt(sys.argv[1:], 'i:f:', ['input=', 
                                                         'filter=',
                                                         ])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in options:
        if opt in ("-i", "--input"):
            file = arg
        if opt in ("-f", "--filter"):
            filter = arg

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

    if filter != None:
        print("Filter set to: "+filter)

    print("--- Up hosts")

    real = 0
    for host in allHosts:
        if nm[host].state() == 'up':

            for proto in nm[host].all_protocols():
                if filter != None:
                    if int(filter) in nm[host][proto].keys():
                        print("{:15s} {:5s} {:6s} {}".format(host, filter, nm[host][proto][int(filter)]['state'], nm[host][proto][int(filter)]['product']))
                        #print("\t"+host+", "+filter+", "+nm[host][proto][int(filter)]['state']+", "+nm[host][proto][int(filter)]['product'])
                else:
                    print("\t"+host)
                    print("\t -"+proto)

                    allPorts = nm[host][proto].keys()
                    allPorts.sort()

                    printTitle = True
                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "open":
                            if printTitle:
                                print("\t Open:")
                                printTitle = False
                            product = nm[host][proto][port]['product']
                            if product != "":
                                product = ", "+product

                            print("\t\t"+str(port)+", "+nm[host][proto][port]['name']+product)

                    printTitle = True
                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "closed":
                            if printTitle:
                                print("\t Closed:")
                                printTitle = False
                            product = nm[host][proto][port]['product']
                            if product != "":
                                product = ", "+product

                            print("\t\t"+str(port)+", "+nm[host][proto][port]['name']+product)

                    printTitle = True
                    for port in allPorts:
                        if nm[host][proto][port]['state'] == "filtered":
                            if printTitle:
                                print("\t Filtered:")
                                printTitle = False
                            product = nm[host][proto][port]['product']
                            if product != "":
                                product = ", "+product

                            print("\t\t"+str(port)+", "+nm[host][proto][port]['name']+product)

                    real = real+1

                    print("")


    if filter == None:
        print("Total hosts up, with ports: "+str(real))
