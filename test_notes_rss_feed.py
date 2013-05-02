import os
import time
import datetime
import calendar
import urllib2
import json
import xml.etree.cElementTree as ElementTree

url_templ = 'http://api.openstreetmap.org/api/0.6/notes/%d.json'


def pubdateToTimestamp(pubdate):
    # Wed, 01 May 2013 18:51:34 +0000
    t = datetime.datetime.strptime(pubdate, "%a, %d %B %Y %H:%M:%S +0000")
    return calendar.timegm(t.utctimetuple())


def readState(filename):
    # Read the state.txt
    sf = open(filename, 'r')

    state = {}
    for line in sf:
        if line[0] == '#':
            continue
        (k, v) = line.split('=')
        state[k] = v.strip().replace("\\:", ":")

    sf.close()

    return state

last_note_id = None

if not os.path.exists('notes_state.txt'):
    print "No notes_state file found to poll note feed."

while True:
    notes_state = readState('notes_state.txt')
    last_note_id = int(notes_state.get('last_note_id', None))

    while True:
        last_note_id += 1
        url = url_templ % last_note_id
        print "Requesting %s" % url
        try:
            result = urllib2.urlopen(url)
            note = json.load(result)
            attrs = note.get('properties')
            geo = note.get('geometry').get('coordinates')
            author = attrs['author'] if 'author' in attrs else 'Anonymous'

            print "%s created a new note near %s, %s: %s: %s" % (author, geo[1], geo[0], attrs['url'].replace('api.openstreetmap', 'osm'), attrs['comments'][0]['text'][:50])

        except urllib2.URLError, e:
            if e.code == 404:
                print "%s doesn't exist. Stopping." % last_note_id
                last_note_id -= 1
                break

    with open('notes_state.txt', 'w') as f:
        f.write('last_note_id=%s\n' % last_note_id)

    time.sleep(60)
