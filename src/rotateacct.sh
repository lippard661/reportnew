#!/bin/sh

# 2025-12-13: Stolen from OpenBSD /etc/daily.
# 2025-12-21: Modified to workaround macOS sa -sq bug (it fails
#   on second and subsequent runs before truncating acct).
# Rotate process accounting logs.

if [ -f /var/account/acct ]; then
    test -f /var/account/acct.2 && \
	/bin/mv -f /var/account/acct.2 /var/account/acct.3
    test -f /var/account/acct.1 && \
	/bin/mv -f /var/account/acct.1 /var/account/acct.2
    test -f /var/account/acct.0 && \
	/bin/mv -f /var/account/acct.0 /var/account/acct.1
    /bin/cp -f /var/account/acct /var/account/acct.0
    # Work around longstanding bug in sa reported in 2012.
    # https://discussions.apple.com/thread/3639471?sortBy=rank
    test -f /var/account/usracct && /bin/rm -rf /var/account/usracct
    /usr/sbin/sa -sq
    /usr/bin/lastcomm -f /var/account/acct.0 | /usr/bin/grep -e ' -[A-Z]*[EMPTU]'
fi

