#!/usr/bin/python

"""detection_ratio.py: Read a file of resource ids (hashes) and retrieve the detection ratios from VirusTotal"""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"


import sys
import urllib2
import urllib
import simplejson
import time

file = open(sys.argv[1], 'r')
hashes = file.readlines()

pkey = open('pkey.conf', 'r').readline()
url = 'https://www.virustotal.com/vtapi/v2/file/report'

def get_25(file=None):
    new_array = []
    while len(file) > 0:
        new_array.append(file.pop().split('\n')[0])
        if len(new_array) is 25:
            return new_array

    return new_array

def get_detections(hashes):
    try:
        parameters = {'resource' : ','.join(map(str, hashes)),
                      'apikey' : pkey }
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        results = simplejson.JSONDecoder().decode(json)
        for result in results:
            print '%s %s / %s' % (result['resource'], result['positives'], result['total'])
    except:
        print '%s X' % hashes

while len(hashes) > 0:
    subset = get_25(hashes)
    get_detections(subset)
    # Stupid avoid rate limiting
    time.sleep(60 / 4)

print 'Done.'
