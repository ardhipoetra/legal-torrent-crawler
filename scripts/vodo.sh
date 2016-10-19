#!/bin/bash

for i in {901..1000}
do
	link=`wget -q --backups=1 http://vodo.net/download/torrent/$i -O - | grep -o '"[^"]*torrent"' | sed 's/"//g'`
	echo "dl from http://vodo.net$link"
	wget --backups=1 --quiet http://vodo.net$link
done
