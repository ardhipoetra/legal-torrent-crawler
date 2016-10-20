import libtorrent
import os
import sys


directory = sys.argv[1]
for fname in os.listdir(directory):
    try:
        info = libtorrent.torrent_info(os.path.join(directory, fname))
        print "magnet:?xt=urn:btih:%s&dn=%s" % (info.info_hash(), info.name())
    except:
        print >> sys.stderr, "Cannot find %s" %os.path.join(directory, fname)
