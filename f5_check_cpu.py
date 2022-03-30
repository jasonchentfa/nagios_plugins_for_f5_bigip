#!/usr/bin/python

# F5 Check CPU Plugin
# This Nagios plugin will get the CPU Usage 5 Min for an F5 BIG-IP.
# Requires the quicksnmp file and pip install pysnmp.
#
# Usage:
# ./f5_check_cpu.py $HOST$ $SNMPCOMMUNITY$ $WARNINGVALUE$ $CRITICALVALUE$
#
# JC 03/2022

from pysnmp import hlapi
import quicksnmp
import sys

def evaluate(cpuUsage,warning,critical,data):
    if cpuUsage >= critical:
        print("CRITICAL" + data)
        sys.exit(2)
    elif cpuUsage >= warning:
        print("WARNING" + data)
        sys.exit(1)
    else:
        print("OK " + data)
        sys.exit(0)

# grab host and community from command line arguments
target = str(sys.argv[1])
community = str(sys.argv[2])
warningValue = int(sys.argv[3])
criticalValue = int(sys.argv[4])

# F5 oid: sysGlobalHostCpuUsageRatio5m
oids = [
    '.1.3.6.1.4.1.3375.2.1.1.2.20.37.0'
]

result = quicksnmp.get(target, oids, hlapi.CommunityData(community))

cpuUsageRatio5m = result['1.3.6.1.4.1.3375.2.1.1.2.20.37.0']

perfData = " | " + 'cpuUsage5Min%=' + str(cpuUsageRatio5m) + "%;" + str(warningValue) + ";" + str(criticalValue)

evaluate(cpuUsageRatio5m, warningValue, criticalValue, perfData)
