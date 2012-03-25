###
# Copyright (c) 2012, Ian Dees
# All rights reserved.
#
#
###

import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks

import datetime
import calendar
import urllib2
from xml.dom.minidom import parse

class OSM(callbacks.Plugin):
    """Add the help for "@plugin help OSM" here
    This should describe *how* to use this plugin."""
    threaded = True

    def isoToTimestamp(self, isotime):
        return datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")
        #return calendar.timegm(t.utctimetuple())

    def prettyDate(self, d):
        diff = datetime.datetime.utcnow() - d
        s = diff.seconds
        if diff.days > 7 or diff.days < 0:
            return 'on %s' % (d.strftime('%d %b %y'))
        elif diff.days == 1:
            return '1 day ago'
        elif diff.days > 1:
            return '{} days ago'.format(diff.days)
        elif s <= 1:
            return 'just now'
        elif s < 60:
            return '{} seconds ago'.format(s)
        elif s < 120:
            return '1 minute ago'
        elif s < 3600:
            return '{} minutes ago'.format(s/60)
        elif s < 7200:
            return '1 hour ago'
        else:
            return '{} hours ago'.format(s/3600)

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
            irc.error('Node %s was not found.' % (node_id))
            return

        dom = parse(xml)
        node_element = dom.getElementsByTagName('node')[0]

        username = node_element.getAttribute('user')
        version = node_element.getAttribute('version')
        timestamp = self.isoToTimestamp(node_element.getAttribute('timestamp'))

        tag_strings = []
        tag_elems = node_element.getElementsByTagName('tag')
        for tag_elem in tag_elems:
            k = tag_elem.getAttribute('k')
            v = tag_elem.getAttribute('v')
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        response = "Node %s: version %s by %s edited %s and has %s" % (node_id,
                                                                       version,
                                                                       username,
                                                                       self.prettyDate(timestamp),
                                                                       tag_str)
        
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
            irc.error('Way %s was not found.' % (way_id))
            return

        dom = parse(xml)
        way_element = dom.getElementsByTagName('way')[0]

        username = way_element.getAttribute('user')
        version = way_element.getAttribute('version')
        timestamp = self.isoToTimestamp(way_element.getAttribute('timestamp'))

        tag_strings = []
        tag_elems = way_element.getElementsByTagName('tag')
        for tag_elem in tag_elems:
            k = tag_elem.getAttribute('k')
            v = tag_elem.getAttribute('v')
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        nd_refs = way_element.getElementsByTagName('nd')
        nd_refs_str = "NO NODES"
        if len(nd_refs) == 1:
            nd_refs_str = "1 NODE"
        elif len(nd_refs) > 1:
            nd_refs_str = "%d nodes" % (len(nd_refs))

        response = "Way %s: version %s by %s edited %s with %s and %s" % \
                (way_id, version, username, self.prettyDate(timestamp), nd_refs_str, tag_str)
        
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
            irc.error('Relation %s was not found.' % (relation_id))
            return

        dom = parse(xml)
        relation_element = dom.getElementsByTagName('relation')[0]

        username = relation_element.getAttribute('user')
        version = relation_element.getAttribute('version')
        timestamp = self.isoToTimestamp(relation_element.getAttribute('timestamp'))

        tag_strings = []
        tag_elems = relation_element.getElementsByTagName('tag')
        for tag_elem in tag_elems:
            k = tag_elem.getAttribute('k')
            v = tag_elem.getAttribute('v')
            tag_strings.append("%s=%s" % (k, v))

        tag_strings = sorted(tag_strings, key=self.tagKeySortKey)

        if len(tag_strings) == 0:
            tag_str = 'no tags.'
        elif len(tag_strings) == 1:
            tag_str = 'tag %s' % (', '.join(tag_strings))
        elif len(tag_strings) > 1:
            tag_str = 'tags %s' % (', '.join(tag_strings))

        members = relation_element.getElementsByTagName('member')
        members_str = "NO MEMBERS"
        if len(members) == 1:
            members_str = "1 member"
        elif len(members) > 1:
            members_str = "%d members" % (len(members))

        response = "Relation %s: version %s by %s edited %s with %s and %s" % \
                (relation_id, version, username, self.prettyDate(timestamp), members_str, tag_str)
        
        irc.reply(response.encode('utf-8'))
    relation = wrap(relation, ['int'])

Class = OSM


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
