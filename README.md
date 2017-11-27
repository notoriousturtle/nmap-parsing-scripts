# Description
Collection of scripts that parse nmap XML output to perform common tasks of an external infrastructure penetration test.

# Required modules
python-nmap, webbrowser

# Contents
parse.py      - Parse, and display nmap output

smtp.py       - Extract all SMTP servers, run smtp-open-relay, and smtp-enum-users

webservers.py - Extract all HTTP servers, open them in the default web browser

sslscan.py    - Extract all HTTP servers, run sslscan on each

scope.py      - Used to help sales scope a project, when an Nmap XML file is provided.

