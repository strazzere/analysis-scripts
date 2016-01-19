#!/usr/bin/python

"""delete_notifications.py: Read a file of notifications ids and remove them from the notification list inside VTi"""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"


import sys
import urllib2
import urllib
import simplejson
import json
import time

pkey = open('pkey.conf', 'r').readline()
base_url = 'https://www.virustotal.com/intelligence/hunting/delete-notifications/programmatic/?key='

def post_delete(notifications):
    req = urllib2.Request(('%s%s') % (base_url, pkey), json.dumps(notifications))
    req.add_header('Content-Type','application/json')
    response = urllib2.urlopen(req)
    data = response.read()
    results = simplejson.JSONDecoder().decode(data)
    return results

def read_file(file_name):
    with open(file_name) as data_file:
        data = json.load(data_file)
        return data

print ' [+] Reading %s...' % sys.argv[1]
notifications = read_file(sys.argv[1])
print ' [+] %s notifications read, attempting to remove...' % len(notifications)
if len(notifications) > 100:
    print ' [!] Need to cover this case sometime! Currently not supported!'
    sys.exit()

# Example response
# {'deleted': 3, 'received': 3, 'result': 1}
result = post_delete(notifications)
if result['received'] != len(notifications):
    print ' [-] Potentially an issue, have %d, however VTi only saw %d!' % (len(notifications), result['received'])
print ' [+] Attempted to delete %d notifications, %d deletions have been confirmed.' % (len(notifications), result['deleted'])
print ' [*] Result code : %d' % (result['result'])
