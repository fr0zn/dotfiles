#!/bin/bash

newsboat -x reload

query_result=`sqlite3 -separator '=%=' $HOME/.newsboat/cache.db 'select pubDate, unread, title, url from rss_item'`

only_unread_sorted=`echo "$query_result" | awk -F"=%=" '$2 == "1" {printf "%s=%%=%s=%%=%s=%%=%s\n", $1, $2, $3, $4}' | sort -rnk1`

echo "$only_unread_sorted" | awk -F"=%=" '{printf "%s ---- %s\n", $3, $4}'
