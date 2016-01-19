#!/usr/bin/python

"""download_hash.py: Download a specified hash from VTi."""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"


import sys
import urllib2

pkey = open('pkey.conf', 'r').readline()
base_url = 'https://www.virustotal.com/intelligence/download/?hash='
api_key = '&apikey='

def get_file(hash):
    req = urllib2.Request('%s%s%s%s' % (base_url, hash, api_key, pkey))
    data = urllib2.urlopen(req).read()
    return data

hash = sys.argv[1]
data = get_file(hash)
try:
    outfile = open(sys.argv[1], 'w')
    outfile.write(data)
    outfile.close
except:
    print 'Issue saving data'

print 'Done.'
