#!/usr/bin/python

"""notification_hunter.py: Attempt to get hunting notifications, filter them and dump out a .hashes and .ids folder for later use"""

__author__ = "Tim 'diff' Strazzere"
__copyright__  = "Copyright 2016, Red Naga"
__license__ = "GPL"
__version__ = "1.0"


import sys
import urllib2
import simplejson
import time

rule_name = sys.argv[1]

pkey = open('pkey.conf', 'r').readline()
base_url = 'https://www.virustotal.com/intelligence/hunting/notifications-feed/?key='
json_key = '&output=json'
page_key = '&next='
filter_key = '&filter='

def get_notifications(filter=None, page=None):
    url = ('%s%s%s') % (base_url, pkey, json_key)
    if page is not None:
        url = ('%s%s%s') % (url, page_key, page) 
    if filter is not None:
        url = ('%s%s%s') % (url, filter_key, filter)
    req = urllib2.Request(url)
    response = urllib2.urlopen(req)
    json = response.read()
    if json is '':
        return None
    results = simplejson.JSONDecoder().decode(json)
    return results

# Taken from http://stackoverflow.com/questions/480214/how-do-you-remove-duplicates-from-a-list-in-python-whilst-preserving-order
def dedupe(seq):
    seen = set()
    seen_add = seen.add
    return [x for x in seq if not (x in seen or seen_add(x))]

# This is likely not really needed due to using the filter parameter now
def filter_for_rule(rule, results):
    hashes = []
    notifications = []
    for result in results['notifications']:
        if result['ruleset_name'] == rule or result['subject'].startswith(rule):
            hashes.append(result['sha1'])
            notifications.append(result['id'])

    return hashes, notifications

print ' [*] Attempting to filter for \'%s\' styled notifications...' % rule_name
feed = get_notifications(filter=rule_name, page=None)
if feed is None:
    print ' [!] Error occured getting notifications, potentially nothing for that rule!'
    sys.exit()
all_hits = []
all_notifications = []
while True:
    print ' [+] Filtering through %d notifications...' % (len(feed['notifications']))
    hits, notifications = filter_for_rule(rule_name, feed)
    all_hits.append(hits)
    all_notifications.append(notifications)
    if feed['next'] is None:
        break
    else:
        print ' [+] Going through pagination...'
        feed = get_notifications(filter=rule_name, page=feed['next'])

hashes_out = open('%s.hashes' % rule_name, 'w')
deduped = dedupe(all_hits[0])
hashes_out.write(simplejson.JSONEncoder().encode(deduped))
hashes_out.close
print ' [+] %d hashes output (%d had been dupes) to %s.hashes' % (len(deduped), len(all_hits[0]) - len(deduped), rule_name)
    
notifications_out = open('%s.ids' % rule_name, 'w')
notifications_out.write(simplejson.JSONEncoder().encode(all_notifications[0]))
notifications_out.close
print ' [+] %d notification ids output to %s.ids' % (len(all_notifications[0]), rule_name)

print 'Done.'
