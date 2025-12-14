#!/bin/sh

# 2025-12-13: Stolen from OpenBSD /etc/daily.
# Rotate process accounting logs.

if [ -f /var/account/acct ]; then
    test -f /var/account/acct.2 && \
	/bin/mv -f /var/account/acct.2 /var/account/acct.3
    test -f /var/account/acct.1 && \
	/bin/mv -f /var/account/acct.1 /var/account/acct.2
    test -f /var/account/acct.0 && \
	/bin/mv -f /var/account/acct.0 /var/account/acct.1
    /bin/cp -f /var/account/acct /var/account/acct.0
    /usr/sbin/sa -sq
    /usr/bin/lastcomm -f /var/account/acct.0 | /usr/bin/grep -e ' -[A-Z]*[EMPTU]'
fi

