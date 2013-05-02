import os
import time
import datetime
import calendar
import urllib2
import xml.etree.cElementTree as ElementTree

url = 'http://api.openstreetmap.org/api/0.6/notes/feed'


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

last_run_newest_timestamp = None

if not os.path.exists('notes_state.txt'):
    print "No notes_state file found to poll note feed."

while True:
    this_run_newest_timestamp = None
    notes_state = readState('notes_state.txt')
    last_run_newest_timestamp = int(notes_state.get('newest_timestamp', None))
    item = dict()

    source = urllib2.urlopen(url)
    print "Requesting %s" % url

    for event, elem in ElementTree.iterparse(source, events=('start', 'end')):
        name = elem.tag
        if event == 'end':
            if name == 'title':
                item['title'] = elem.text
            elif name == 'author':
                item['author'] = elem.text
            elif name == '{http://www.w3.org/2003/01/geo/wgs84_pos#}lat':
                item['lat'] = float(elem.text)
            elif name == '{http://www.w3.org/2003/01/geo/wgs84_pos#}long':
                item['lon'] = float(elem.text)
            elif name == 'link':
                item['link'] = elem.text
            elif name == 'pubDate':
                item['time'] = pubdateToTimestamp(elem.text)
            elif name == 'description':
                item['description'] = elem.text
            elif name == 'item':
                if this_run_newest_timestamp is None or item['time'] > this_run_newest_timestamp:
                    this_run_newest_timestamp = item['time']

                if last_run_newest_timestamp is not None and last_run_newest_timestamp == this_run_newest_timestamp:
                    print "Last run had a newest time of %s and this run was %s, so stopping here." % (last_run_newest_timestamp, this_run_newest_timestamp)
                    break

                if item['title'].startswith('new note'):
                    author = item['author'] if 'author' in item else 'Anonymous'
                    print "%s created a new note near %s, %s: %s: %s" % (author, item['lat'], item['lon'], item['link'].replace('api.openstreetmap', 'osm'), item['description'])
                item = dict()

    if last_run_newest_timestamp != this_run_newest_timestamp:
        last_run_newest_timestamp = this_run_newest_timestamp
        with open('notes_state.txt', 'w') as f:
            f.write('newest_timestamp=%s\n' % last_run_newest_timestamp)

    time.sleep(60)
