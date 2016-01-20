#!/usr/bin/python

"""download_hash.py: Download a specified hashes from VTi."""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"

import os
import sys
import urllib2
import json
from progressbar import ProgressBar

pbar = ProgressBar()

pkey = open('pkey.conf', 'r').readline()
base_url = 'https://www.virustotal.com/intelligence/download/?hash='
api_key = '&apikey='

def get_file(hash):
    req = urllib2.Request('%s%s%s%s' % (base_url, hash, api_key, pkey))
    data = urllib2.urlopen(req).read()
    return data

def read_file(file_name):
    with open(file_name) as data_file:
        data = json.load(data_file)
        return data

hashes = read_file(sys.argv[1])
print(' [+] Read %d hashes, attempting to get them...' % len(hashes))

path_name = sys.argv[1].split('.')[0]
if not os.path.exists(path_name):
    os.makedirs(path_name)

for hash in pbar(hashes):
    data = get_file(hash)
    try:
        outfile = open(('%s/%s' % (path_name, hash)), 'w')
        outfile.write(data)
        outfile.close
    except:
        print('Issue saving data for %s' % hash)

print('\nDone.')
