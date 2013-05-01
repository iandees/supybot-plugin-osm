###
# Copyright (c) 2012, Ian Dees
# All rights reserved.
#
#
###

from supybot.commands import *
import supybot.ircmsgs as ircmsgs
import supybot.callbacks as callbacks
import supybot.schedule as schedule
import supybot.world as world
import supybot.log as log

import traceback

import gzip
import StringIO
import itertools
import datetime
import calendar
import urllib2
import urllib
import xml.etree.cElementTree as ElementTree
import os
import json


class OscHandler():
    def __init__(self):
        self.changes = {}
        self.nodes = {}
        self.ways = {}
        self.relations = {}
        self.action = ""
        self.primitive = {}
        self.missingNds = set()

    def startElement(self, name, attributes):
        if name in ('modify', 'delete', 'create'):
            self.action = name
        if name in ('node', 'way', 'relation'):
            self.primitive['type'] = name
            self.primitive['id'] = int(attributes['id'])
            self.primitive['version'] = int(attributes['version'])
            self.primitive['changeset'] = int(attributes['changeset'])
            self.primitive['uid'] = int(attributes.get('uid'))
            self.primitive['user'] = attributes.get('user').encode('utf-8')
            self.primitive['timestamp'] = isoToTimestamp(attributes['timestamp'])
            self.primitive['tags'] = {}
            self.primitive['action'] = self.action
        if name == 'node':
            self.primitive['lat'] = float(attributes['lat'])
            self.primitive['lon'] = float(attributes['lon'])
        elif name == 'tag':
            key = attributes['k'].encode('utf-8')
            val = attributes['v'].encode('utf-8')
            self.primitive['tags'][key] = val
        elif name == 'way':
            self.primitive['nodes'] = []
        elif name == 'relation':
            self.primitive['members'] = []
        elif name == 'nd':
            ref = int(attributes['ref'])
            self.primitive['nodes'].append(ref)
            if ref not in self.nodes:
                self.missingNds.add(ref)
        elif name == 'member':
            self.primitive['members'].append(
                                    {
                                     'type': attributes['type'],
                                     'role': attributes['role'].encode('utf-8'),
                                     'ref': attributes['ref']
                                    })

    def endElement(self, name):
        if name == 'node':
            self.nodes[self.primitive['id']] = self.primitive
        elif name == 'way':
            self.ways[self.primitive['id']] = self.primitive
        elif name == 'relation':
            self.relations[self.primitive['id']] = self.primitive
        if name in ('node', 'way', 'relation'):
            self.primitive = {}

def isoToTimestamp(isotime):
    t = datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
    return calendar.timegm(t.utctimetuple())

def parseOsm(source, handler):
    for event, elem in ElementTree.iterparse(source, events=('start', 'end')):
        if event == 'start':
            handler.startElement(elem.tag, elem.attrib)
        elif event == 'end':
            handler.endElement(elem.tag)
        elem.clear()

_new_uid_edit_region_channels = {
    "#osm-ar": ("ar",),
    "#osm-au": ("au",),
    "#osm-bd": ("bd",),
    "#osm-be": ("be",),
    "#osm-br": ("br",),
    "#osm-by": ("by",),
    "#osm-ca": ("ca",),
    "#osm-ch": ("ch",),
    "#osm-de-announce": ("de",),
    "#osm-dk": ("dk",),
    "#osm-do": ("do",),
    "#osm-es": ("es",),
    "#osm-fi": ("fi",),
    "#osm-fr": ("fr",),
    "#osm-gb": ("gb",),
    "#osm-ht": ("ht",),
    "#osm-ie": ("ie",),
    "#osm-it": ("it",),
    "#osm-ja": ("jp",),
    "#osm-lv": ("lv",),
    "#osm-ly": ("ly",),
    "#osm-nl": ("nl",),
    "#osm-no": ("no",),
    "#osm-nl": ("nl",),
    "#osm-no": ("no",),
    "#osm-ph": ("ph",),
    "#osm-pl": ("pl",),
    "#osm-ps": ("ps",),
    "#osm-ru": ("ru",),
    "#OSM.se": ("se",),
    "#osm-ua": ("ua",),
    "#osm-us": ("us",),
    "#osm-za": ("za",),
}

class OSM(callbacks.Plugin):
    """Add the help for "@plugin help OSM" here
    This should describe *how* to use this plugin."""
    threaded = True

    def __init__(self, irc):
        self.__parent__ = super(OSM, self)
        self.__parent__.__init__(irc)
        self.seen_changesets = {}
        self.irc = irc
        self._start_polling()

    def die(self):
        self._stop_polling()
        self.__parent__.die()

    def _start_polling(self):
        log.info('Start polling.')
        schedule.addPeriodicEvent(self._minutely_diff_poll, 60, now=True, name='minutely_poll')

    def _stop_polling(self):
        log.info('Stop polling.')
        schedule.removeEvent('minutely_poll')

    def readState(self):
        # Read the state.txt
        sf = open('state.txt', 'r')

        state = {}
        for line in sf:
            if line[0] == '#':
                continue
            (k, v) = line.split('=')
            state[k] = v.strip().replace("\\:", ":")

        sf.close()

        return state

    def fetchNextState(self, currentState):
        stateTs = datetime.datetime.strptime(currentState['timestamp'], "%Y-%m-%dT%H:%M:%SZ")
        nextTs = stateTs + datetime.timedelta(minutes=1)

        if datetime.datetime.utcnow() < nextTs:
            # The next timestamp is in the future, so don't try to get it.
            return False

        # Download the next state file
        nextSqn = int(currentState['sequenceNumber']) + 1
        sqnStr = str(nextSqn).zfill(9)
        url = "http://planet.openstreetmap.org/replication/minute/%s/%s/%s.state.txt" % (sqnStr[0:3], sqnStr[3:6], sqnStr[6:9])
        try:
            u = urllib2.urlopen(url)
            statefile = open('state.txt', 'w')
            statefile.write(u.read())
            statefile.close()
        except Exception, e:
            print e
            return False

        return True

    
    def _minutely_diff_poll(self):
        try:
            if not os.path.exists('state.txt'):
                log.error("No state file found to poll minutelies.")
                return

            seen_uids = {}
            seen_changesets = self.seen_changesets

            state = self.readState()

            while self.fetchNextState(state):
                state = self.readState()

                # Grab the next sequence number and build a URL out of it
                sqnStr = state['sequenceNumber'].zfill(9)
                url = "http://planet.openstreetmap.org/replication/minute/%s/%s/%s.osc.gz" % (sqnStr[0:3], sqnStr[3:6], sqnStr[6:9])

                log.info("Downloading change file (%s)." % (url))
                content = urllib2.urlopen(url)
                content = StringIO.StringIO(content.read())
                gzipper = gzip.GzipFile(fileobj=content)

                handler = OscHandler()
                parseOsm(gzipper, handler)

                for (id, prim) in itertools.chain(handler.nodes.iteritems(), handler.ways.iteritems(), handler.relations.iteritems()):

                    changeset_id = str(prim['changeset'])
                    action = prim['action']
                    prim_type = prim['type']

                    changeset_data = seen_changesets.get(changeset_id, {})
                    cs_type_data = changeset_data.get(prim_type, {})
                    cs_type_data[action] = cs_type_data.get(action, 0) + 1
                    cs_type_data['total_changes'] = cs_type_data.get('total_changes', 0) + 1
                    changeset_data[prim_type] = cs_type_data
                    changeset_data['total_changes'] = changeset_data.get('total_changes', 0) + 1
                    changeset_data['last_modified'] = prim['timestamp']
                    seen_changesets[changeset_id] = changeset_data

                    uid = str(prim['uid'])
                    if uid in seen_uids:
                        continue
                    else:
                        seen_uids[str(prim['uid'])] = {'changeset': prim['changeset'],
                                                       'username': prim['user']}

                    if 'lat' in prim and 'lat' not in seen_uids[str(prim['uid'])]:
                        seen_uids[str(prim['uid'])]['lat'] = prim['lat']
                        seen_uids[str(prim['uid'])]['lon'] = prim['lon']

                #log.info("Changeset actions: %s" % json.dumps(seen_changesets))

                # Check the changesets for anomolies
                now = datetime.datetime.utcnow()
                cs_flags = []
                for (id, cs_data) in seen_changesets.items():
                    last_modified = datetime.datetime.utcfromtimestamp(cs_data['last_modified'])
                    age = (now - last_modified).seconds
                    if age > 3600:
                        log.info("Forgetting changeset %s because it's been %s seconds since we last saw it" % (id, age))
                        del seen_changesets[id]
                    
                    total_changes = cs_data['total_changes']
                    node_changes = cs_data.get('node', {}).get('total_changes', 0)
                    way_changes = cs_data.get('way', {}).get('total_changes', 0)
                    relation_changes = cs_data.get('relation', {}).get('total_changes', 0)
                    node_pct = node_changes / float(total_changes)
                    way_pct = way_changes / float(total_changes)
                    relation_pct = relation_changes / float(total_changes)
                    
                    # Flag a changeset that's big and made up of all one primitive type
                    if total_changes > 1000 and (node_pct > 0.9 or way_pct > 0.9 or relation_pct > 0.9):
                        cs_flags.append((id, "it is mostly changes to one data type"))
                    
                    creates = cs_data.get('node', {}).get('create', 0) + cs_data.get('way', {}).get('create', 0) + cs_data.get('relation', {}).get('create', 0)
                    mods = cs_data.get('node', {}).get('modify', 0) + cs_data.get('way', {}).get('modify', 0) + cs_data.get('relation', {}).get('modify', 0)
                    deletes = cs_data.get('node', {}).get('delete', 0) + cs_data.get('way', {}).get('delete', 0) + cs_data.get('relation', {}).get('delete', 0)
                    create_pct = creates / float(total_changes)
                    mod_pct = mods / float(total_changes)
                    delete_pct = deletes / float(total_changes)

                    # Flag a changeset that's big and made up of only one change type
                    if total_changes > 1000 and (create_pct > 0.9 or mod_pct > 0.9 or delete_pct > 0.9):
                        cs_flags.append((id, "it is mostly creates, modifies, or deletes"))

                    log.info("CS %s: %s changes; %.2fn %.2fw %.2fr; %.2fc %.2fm %.2fd" % (id, total_changes, node_pct, way_pct, relation_pct, create_pct, mod_pct, delete_pct))
                
                # Tell the channel about these problems
                irc = world.ircs[0]
                for (cs_id, reason) in cs_flags:
                    if cs_id in seen_changesets and seen_changesets[cs_id].get('alerted_already'):
                        continue
                    
                    response = "Changeset %s is weird because %s. http://osm.org/browse/changeset/%s" % (cs_id, reason, cs_id)

                    log.info(response)
                    for chan in irc.state.channels:
                        if chan == "#osm-bot":
                            msg = ircmsgs.privmsg(chan, response)
                            world.ircs[0].queueMsg(msg)
                    seen_changesets[cs_id]['alerted_already'] = True

            log.info("There were %s users editing this time." % len(seen_uids))

            f = open('uid.txt', 'r')
            for line in f:
                for uid in seen_uids.keys():
                    if uid in line:
                        seen_uids.pop(uid)
                        continue
                if len(seen_uids) == 0:
                    break
            f.close()

            f = open('uid.txt', 'a')
            for (uid, data) in seen_uids.iteritems():
                f.write('%s\t%s\n' % (data['username'], uid))

                location = ""
                country_code = None
                if 'lat' in data:
                    try:
                        urldata = urllib2.urlopen('http://nominatim.openstreetmap.org/reverse?format=json&lat=%s&lon=%s' % (data['lat'], data['lon']))

                        info = json.load(urldata)
                        if 'address' in info:
                            address = info.get('address')

                            country_code = address.get('country_code')

                            if 'country' in address:
                                location = address.get('country')
                            if 'state' in address:
                                location = "%s, %s" % (address.get('state'), location)
                            if 'county' in address:
                                location = "%s, %s" % (address.get('county'), location)
                            if 'administrative' in address:
                                location = "%s, %s" % (address.get('administrative'), location)
                            if 'city' in address:
                                location = "%s, %s" % (address.get('city'), location)
                            if 'hamlet' in address:
                                location = "%s, %s" % (address.get('hamlet'), location)

                            location = " near %s" % (location)
                            location = location.encode('utf-8')
                    except urllib2.HTTPError as e:
                        log.warn("HTTP problem when looking for edit location: %s" % (e))

                response = "%s just started editing%s with changeset http://osm.org/browse/changeset/%s" % (data['username'], location, data['changeset'])
                log.info(response)
                irc = world.ircs[0]
                for chan in irc.state.channels:
                    if chan == "#osm-bot" or country_code in _new_uid_edit_region_channels.get(chan, ()):
                        msg = ircmsgs.privmsg(chan, response)
                        world.ircs[0].queueMsg(msg)

            f.close()

        except Exception as e:
            log.error("Exception processing new users: %s" % traceback.format_exc(e))

    def isoToTimestamp(self, isotime):
        return datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")

    def prettyDate(self, d):
        diff = datetime.datetime.utcnow() - d
        s = diff.seconds
        if diff.days > 7 or diff.days < 0:
            return 'on %s' % (d.strftime('%d %b %Y'))
        elif diff.days == 1:
            return '1 day ago'
        elif diff.days > 1:
            return '{0} days ago'.format(diff.days)
        elif s <= 1:
            return 'just now'
        elif s < 60:
            return '{0} seconds ago'.format(s)
        elif s < 120:
            return '1 minute ago'
        elif s < 3600:
            return '{0} minutes ago'.format(s/60)
        elif s < 7200:
            return '1 hour ago'
        else:
            return '{0} hours ago'.format(s/3600)

    def tagKeySortKey(self, key):
        ret = key.lower()
        if ret.startswith('name'):
            return 'AAAAA'
        elif ret.startswith('highway'):
            return 'AAAAB'
        elif ret.startswith('amenity'):
            return 'AAAAC'
        elif ret.startswith('shop'):
            return 'AAAAD'
        else:
            return ret

    def node(self, irc, msg, args, node_id):
        """<node_id>

        Shows information about the specified OSM node ID."""
        baseUrl = "http://osm.org"

        if not node_id:
            irc.error('You forgot to give me a node ID.')
            return

        try:
            xml = urllib2.urlopen('%s/api/0.6/node/%d' % (baseUrl, node_id))
        except urllib2.HTTPError as e:
            if e.code == 410:
                last_mod = datetime.datetime.strptime(e.headers.get('Last-Modified'), '%a, %d %b %Y %H:%M:%S %Z')
                irc.reply('Node %s was deleted %s ago.' % (node_id, self.prettyDate(last_mod)))
            elif e.code == 404:
                irc.error('Node %s was not found.' % (node_id))
            else:
                irc.error('Could not reach server for node %s.' % (node_id))
            return

        tree = ElementTree.ElementTree(file=xml)
        node_element = tree.find("node")

        username = node_element.attrib['user']
        version = node_element.attrib['version']
        timestamp = self.isoToTimestamp(node_element.attrib['timestamp'])

        tag_strings = []
        tag_elems = node_element.findall('tag')
        for tag_elem in tag_elems:
            k = tag_elem.get('k')
            v = tag_elem.get('v')
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        response = "Node %s: version %s by %s edited %s and has %s http://osm.org/browse/node/%s" % (node_id,
                                                                          version,
                                                                          username,
                                                                          self.prettyDate(timestamp),
                                                                          tag_str,
                                                                          node_id)

        irc.reply(response.encode('utf-8'))
    node = wrap(node, ['int'])

    def way(self, irc, msg, args, way_id):
        """<way_id>

        Shows information about the specified OSM way ID."""
        baseUrl = "http://osm.org"

        if not way_id:
            irc.error('You forgot to give me a way ID.')
            return

        try:
            xml = urllib2.urlopen('%s/api/0.6/way/%d' % (baseUrl, way_id))
        except urllib2.HTTPError as e:
            if e.code == 410:
                last_mod = datetime.datetime.strptime(e.headers.get('Last-Modified'), '%a, %d %b %Y %H:%M:%S %Z')
                irc.reply('Way %s was deleted %s ago.' % (way_id, self.prettyDate(last_mod)))
            elif e.code == 404:
                irc.error('Way %s was not found.' % (way_id))
            else:
                irc.error('Could not reach server for way %s.' % (way_id))
            return

        tree = ElementTree.ElementTree(file=xml)
        way_element = tree.find('way')

        username = way_element.attrib['user']
        version = way_element.attrib['version']
        timestamp = self.isoToTimestamp(way_element.attrib['timestamp'])

        tag_strings = []
        tag_elems = way_element.findall('tag')
        for tag_elem in tag_elems:
            k = tag_elem.attrib['k']
            v = tag_elem.attrib['v']
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        nd_refs = way_element.findall('nd')
        nd_refs_str = "NO NODES"
        if len(nd_refs) == 1:
            nd_refs_str = "1 NODE"
        elif len(nd_refs) > 1:
            nd_refs_str = "%d nodes" % (len(nd_refs))

        response = "Way %s: version %s by %s edited %s with %s and %s http://osm.org/browse/way/%s" % \
                (way_id, version, username, self.prettyDate(timestamp), nd_refs_str, tag_str, way_id)

        irc.reply(response.encode('utf-8'))
    way = wrap(way, ['int'])

    def relation(self, irc, msg, args, relation_id):
        """<relation_id>

        Shows information about the specified OSM relation ID."""
        baseUrl = "http://osm.org"

        if not relation_id:
            irc.error('You forgot to give me a relation ID.')
            return

        try:
            xml = urllib2.urlopen('%s/api/0.6/relation/%d' % (baseUrl, relation_id))
        except urllib2.HTTPError as e:
            if e.code == 410:
                last_mod = datetime.datetime.strptime(e.headers.get('Last-Modified'), '%a, %d %b %Y %H:%M:%S %Z')
                irc.reply('Relation %s was deleted %s ago.' % (relation_id, self.prettyDate(last_mod)))
            elif e.code == 404:
                irc.error('Relation %s was not found.' % (relation_id))
            else:
                irc.error('Could not reach server for relation %s.' % (relation_id))
            return

        tree = ElementTree.ElementTree(file=xml)
        relation_element = tree.find('relation')

        username = relation_element.attrib['user']
        version = relation_element.attrib['version']
        timestamp = self.isoToTimestamp(relation_element.attrib['timestamp'])

        tag_strings = []
        tag_elems = relation_element.findall('tag')
        for tag_elem in tag_elems:
            k = tag_elem.attrib['k']
            v = tag_elem.attrib['v']
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        members = relation_element.findall('member')
        members_str = "NO MEMBERS"
        if len(members) == 1:
            members_str = "1 member"
        elif len(members) > 1:
            members_str = "%d members" % (len(members))

        response = "Relation %s: version %s by %s edited %s with %s and %s http://osm.org/browse/relation/%s" % \
                (relation_id, version, username, self.prettyDate(timestamp), members_str, tag_str, relation_id)

        irc.reply(response.encode('utf-8'))
    relation = wrap(relation, ['int'])

    def changeset(self, irc, msg, args, changeset_id):
        """<changeset_id>

        Shows information about the specified OSM changeset ID."""
        baseUrl = "http://osm.org"

        if not changeset_id:
            irc.error('You forgot to give me a changeset ID.')
            return

        try:
            xml = urllib2.urlopen('%s/api/0.6/changeset/%d' % (baseUrl, changeset_id))
        except urllib2.HTTPError as e:
            irc.error('Changeset %s was not found.' % (changeset_id))
            return

        tree = ElementTree.ElementTree(file=xml)
        changeset_element = tree.find('changeset')

        username = changeset_element.attrib['user']
        currently_open = changeset_element.attrib['open']
        created = self.isoToTimestamp(changeset_element.attrib['created_at'])

        if currently_open == 'true':
            length_str = "(still open)"
        elif currently_open == 'false':
            closed = self.isoToTimestamp(changeset_element.attrib['closed_at'])
            length_str = "open %s minutes" % ((closed - created).seconds / 60)

        tag_strings = []
        tag_elems = changeset_element.findall('tag')
        for tag_elem in tag_elems:
            k = tag_elem.attrib['k']
            v = tag_elem.attrib['v']
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        response = "Changeset %s by %s opened %s %s with %s" % \
                (changeset_id, username, self.prettyDate(created), length_str, tag_str)

        irc.reply(response.encode('utf-8'))
    changeset = wrap(changeset, ['int'])

    def last_edit(self, irc, msg, args, username):
        """<username>

        Shows information about the last edit for the given user."""
        baseUrl = "http://osm.org"

        if not username:
            irc.error('You forgot to give me a username.')
            return

        quoted_uname = username
        quoted_uname = urllib.quote(quoted_uname)

        try:
            xml = urllib2.urlopen('%s/user/%s/edits/feed' % (baseUrl, quoted_uname))
        except urllib2.HTTPError as e:
            irc.error('Username %s was not found.' % (username))
            return
        except Exception as e:
            irc.error("Could not parse the user's changeset feed.")
            log.error(traceback.format_exc(e))
            return

        tree = ElementTree.ElementTree(file=xml)
        first_entry = tree.find('{http://www.w3.org/2005/Atom}entry')

        if first_entry is None:
            irc.error("Looks like %s doesn't have any edits." % (username))
            return

        author = first_entry.findtext('{http://www.w3.org/2005/Atom}author/{http://www.w3.org/2005/Atom}name')
        timestamp = first_entry.findtext('{http://www.w3.org/2005/Atom}updated')
        entry_id = first_entry.findtext('{http://www.w3.org/2005/Atom}id')

        if author != username:
            # It looks like there's a bug where the API will give back the most recent user's edit feed
            # instead of a 404
            irc.error('Unknown username. Was "%s" but asked for "%s"' % (author, username))
            return

        # Strip off the word "Changeset " from the title to get the number
        changeset_id = entry_id[46:]

        updated = self.isoToTimestamp(timestamp)

        response = "User %s last edited %s with changeset %s" % (author, self.prettyDate(updated), changeset_id)

        irc.reply(response.encode('utf-8'))
    lastedit = wrap(last_edit, ['anything'])

    def taginfo(self, irc, msg, args, tag_query):
        """<tag key>[=<tag value>|*]

        Shows information about the specified tag key/value combination."""
        baseUrl = "http://taginfo.openstreetmap.org"

        if not tag_query:
            irc.error('You forgot to give me a tag_query.')
            return

        k = None
        v = None
        if '=' in tag_query:
            (k,v) = tag_query.split('=')
            if '*' == v:
                v = None
        else:
            k = tag_query

        try:
            if k is None:
                irc.error("I don't know how to parse that key/value pair.")
                return
            elif v is None:
                j = urllib2.urlopen('%s/api/2/db/keys/overview?key=%s' % (baseUrl, urllib.quote(k)), timeout=30.0)
                data = json.load(j)

                response = "Tag %s has %s values and appears %s times in the planet. http://taginfo.osm.org/keys/%s" % (k, data['all']['values'], data['all']['count'], urllib.quote(k))
            else:
                j = urllib2.urlopen('%s/api/2/db/tags/overview?key=%s&value=%s' % (baseUrl, urllib.quote(k), urllib.quote(v)), timeout=30.0)
                data = json.load(j)

                response = "Tag %s=%s appears %s times in the planet. http://taginfo.osm.org/tags/%s" % (k, v, data['all']['count'], urllib.quote("%s=%s" % (k,v)))
            irc.reply(response.encode('utf-8'))
        except urllib2.URLError as e:
            irc.error('There was an error connecting to the taginfo server. Try again later.')
            return
    taginfo = wrap(taginfo, ['anything'])

Class = OSM


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
