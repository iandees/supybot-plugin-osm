###
# Copyright (c) 2012, Ian Dees
# All rights reserved.
#
#
###

import supybot.utils as utils
from supybot.commands import *
import supybot.plugins as plugins
import supybot.ircmsgs as ircmsgs
import supybot.ircutils as ircutils
import supybot.callbacks as callbacks
import supybot.schedule as schedule
import supybot.world as world
import supybot.log as log

import traceback

import datetime
import calendar
import urllib2
from xml.etree.cElementTree import ElementTree
import os

class OSM(callbacks.Plugin):
    """Add the help for "@plugin help OSM" here
    This should describe *how* to use this plugin."""
    threaded = True

    def __init__(self, irc):
        self.__parent__ = super(OSM, self)
        self.__parent__.__init__(irc)
        self.last_update_agreed = 0
        self._start_polling()
        self.irc = irc

    def die(self):
        self._stop_polling()
        self.__parent__.die()

    def _start_polling(self):
        self.poll_period = 300
        schedule.addPeriodicEvent(self._poll, self.poll_period, now=True, name=self.name())

    def _stop_polling(self):
        schedule.removeEvent(self.name())

    def _poll(self):
        try:
            # Grab the latest users_agreed
            log.info('Starting to fetch a new users_agreed.txt')
            req = urllib2.Request('http://planet.openstreetmap.org/users_agreed/users_agreed.txt')
            if self.last_update_agreed:
                req.add_header("If-Modified-Since", self.last_update_agreed)
            
            try:
                resp = urllib2.urlopen(req)
                self.last_update_agreed = resp.info().getheader("Last-Modified")
                log.info('Last modified at %s' % (self.last_update_agreed))

                # Write it out to a new file
                new_file = open('users_agreed.new.txt', 'w')
                new_file.write(resp.read())
                new_file.close()
                log.info('Finished writing to users_agreed.new.txt')
            except urllib2.HTTPError as e:
                if e.code == 304:
                    log.info('users_agreed not modified this time around')
                    return
                else:
                    raise e

            users_newly_agreed = []
            users_newly_disagreed = []

            # Compare to the one we already have
            if os.path.exists('users_agreed.txt'):
                new_file = open('users_agreed.new.txt', 'r')
                old_file = open('users_agreed.txt', 'r')
                newset = set(new_file.readlines())
                oldset = set(old_file.readlines())
                old_file.close()
                new_file.close()

                users_newly_agreed = newset - oldset
                users_newly_disagreed = oldset - newset

                # Strip whitespace and convert to ints
                users_newly_agreed = [int(x) for x in users_newly_agreed]
                users_newly_disagreed = [int(x) for x in users_newly_disagreed]

            log.info('New agreers: %s, No longer agreeing: %s' % (users_newly_agreed, users_newly_disagreed))

            # Move the new file over to the "old" spot
            os.rename('users_agreed.new.txt', 'users_agreed.txt')

            # Look up all the usernames
            usernames = {}
            for userid in set(users_newly_agreed + users_newly_disagreed):
                req = urllib2.urlopen('http://tools.geofabrik.de/username/%s' % (userid))
                username = req.read()
                usernames[userid] = username.rstrip('\r\n')

            users_newly_agreed = [usernames[x] for x in users_newly_agreed]
            users_newly_disagreed = [usernames[x] for x in users_newly_disagreed]

            # Tell people the good news!
            for user in users_newly_agreed:
                response = 'User %s has agreed! http://osm.org/user/%s' % (user, user)
                irc = world.ircs[0]
                for chan in irc.state.channels:
                    msg = ircmsgs.privmsg(chan, response)
                    world.ircs[0].queueMsg(msg)
        except Exception as e:
            log.error(traceback.format_exc(e))

    def isoToTimestamp(self, isotime):
        return datetime.datetime.strptime(isotime, "%Y-%m-%dT%H:%M:%SZ")

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

        tree = ElementTree(file=xml)
        node_element = tree.find("node")

        username = node_element.attrib['user']
        version = node_element.attrib['version']
        timestamp = self.isoToTimestamp(node_element.attrib['timestamp'])

        tag_strings = []
        tag_elems = node_element.findall('tag')
        for tag_elem in tag_elems:
            k = tag_elem.attrib('k')
            v = tag_elem.attrib('v')
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

        tree = ElementTree(file=xml)
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

        tree = ElementTree(file=xml)
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

        response = "Relation %s: version %s by %s edited %s with %s and %s" % \
                (relation_id, version, username, self.prettyDate(timestamp), members_str, tag_str)
        
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

        tree = ElementTree(file=xml)
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

        try:
            xml = urllib2.urlopen('%s/user/%s/edits/feed' % (baseUrl, username))
        except urllib2.HTTPError as e:
            irc.error('Username %s was not found.' % (username))
            return

        tree = ElementTree(file=xml)
        first_entry = tree.find('{http://www.w3.org/2005/Atom}entry')

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

Class = OSM


# vim:set shiftwidth=4 softtabstop=4 expandtab textwidth=79:
