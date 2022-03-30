#!/usr/bin/python

# F5 Check TMM Memory Plugin
# This Nagios plugin will get the TMM memory usage for an F5 BIG-IP.
# Requires the quicksnmp file and pip install pysnmp.
#
# Usage:
# ./f5_check_tmm_memory.py $HOST$ $SNMPCOMMUNITY$ $WARNINGVALUE$ $CRITICALVALUE$
#
# JC 03/2022

from pysnmp import hlapi
import quicksnmp
import sys

def calculateMemUsed(results):
    percentage = results['1.3.6.1.4.1.3375.2.1.8.2.3.1.32.3.48.46.48']*100.0/results['1.3.6.1.4.1.3375.2.1.8.2.3.1.31.3.48.46.48']
    limit_float = round(percentage, 2)
    return(limit_float)

def evaluate(memory, warning, critical, data):
    if memory >= critical:
        print("CRITICAL" + data)
        sys.exit(2)
    elif memory >= warning:
        print("WARNING" + data)
        sys.exit(1)
    else:
        print("OK" + data)
        sys.exit(0)

# grab host and community from command line arguments
target = str(sys.argv[1])
community = str(sys.argv[2])
warningValue = float(sys.argv[3])
criticalValue = float(sys.argv[4])

# F5 oids: sysTmmStatMemoryTotal and sysTmmStatMemoryUsed
oids = [
    '.1.3.6.1.4.1.3375.2.1.8.2.3.1.31.3.48.46.48',
    '.1.3.6.1.4.1.3375.2.1.8.2.3.1.32.3.48.46.48'
]

result = quicksnmp.get(target, oids, hlapi.CommunityData(community))

memoryUsed = calculateMemUsed(result)

perfData = " | " + '%used=' + str(memoryUsed) + "%;" + str(warningValue) + ";" + str(criticalValue)

evaluate(memoryUsed, warningValue, criticalValue, perfData)
