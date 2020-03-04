#!/usr/bin/python

import sys
import os
import re
from subprocess import Popen, PIPE, DEVNULL

badSerials = {}

def loadaffectedCerts(caaFile):
    with open(caaFile, 'r') as fp:
        for line in fp:
            arr = line.split()
            badSerials[arr[1]] = True

def isAffected(serial):
    return serial in badSerials

def getSerial(hostname):
    cmd = "timeout 0.5 openssl s_client -connect %s:443 -servername %s -showcerts" % (hostname, hostname)
    out = Popen(cmd.split(), stdout=PIPE, stderr=DEVNULL)

    cmd2 = "openssl x509 -text -noout"
    out2 = Popen(cmd2.split(), stdin=out.stdout, stderr=DEVNULL, stdout=PIPE)
    stdout, stderr = out2.communicate()
    res = stdout.decode("UTF-8")

    serial = ""
    m = re.search(".*Serial\sNumber:\s+([a-z0-9:]+)", res)
    if m:
        serial = m.group(1).replace(":", "")

    return serial

def processList(hostnameListFile):
    affectedCerts = {}
    with open(hostnameListFile) as fp:
        for hostname in fp:
            hostname = hostname.rstrip()
            ser = getSerial(hostname)
            if len(ser) > 0:
                print("%-64s %-40s" % (hostname, ser), end='')
                if isAffected(ser):
                    print("AFFECTED!")
                    affectedCerts[hostname] = ser
                else:
                    print("%14s" % ("Not affected"))

    print("\nFound %d affected certificates." % (len(affectedCerts)))
    for h in affectedCerts:
        print("%-64s %40s" % (h, affectedCerts[h]))

if len(sys.argv) < 2:
    print("Usage: %s <hostnameList>" %(sys.argv[0]))
    sys.exit(1)

if not os.path.isfile('./caa-rechecking-incident-affected-serials.txt'):
    print("caa-rechecking-incident-affected-serials.txt not found.")
    print("You need to download and gunzip https://d4twhgtvn0ff5.cloudfront.net/caa-rechecking-incident-affected-serials.txt.gz into the same path as this script.")
    sys.exit(1)

if not os.path.isfile(sys.argv[1]):
    print("File '%s' does not exist." % (sys.argv[1]))
    sys.exit(1)

loadaffectedCerts('./caa-rechecking-incident-affected-serials.txt')
processList(sys.argv[1])
