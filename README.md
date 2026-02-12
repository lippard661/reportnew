# reportnew
Perl script to monitor logs for issues and issue alert emails, with some correlation capability within a log.

Supports syslog, cyclog, multilog, BSD (and macOS) and Linux process accounting logs, and Linux journal logs. Runs periodically rather than continuously.

Supports include files which may be signed (requires Signify.pm).

Also available at https://www.discord.org/lippard/software

reportnew-1.31.tgz is a Legion of Dynamic Discord signify-signed OpenBSD package. Signify public key is https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

Current version is reportnew-1.31 of 11 February 2026.

This version supports privilege separation on OpenBSD, macOS, and Linux, which requires the perl modules IO::FDPass (libio-fdpass-perl on Linux),
Privileges::Drop (libprivileges-drop-perl on Linux), and either JSON::MaybeXS (libjson-maybexs-perl on Linux) or standard but slower module
JSON::PP. The non-standard modules are also on CPAN.

Privileges::Drop fails with perl 5.34.1 which is the release on macOS Tahoe 26.1, but works properly with perl 5.40.2 which is the current stable Homebrew
release. Workarounds are either use the Homebrew perl or patch Privileges::Drop on the lines beginning with my %GIDHash and my %EGIDHash to insert
"grep { $_ != 4294967295 }" immediately before "split(\s/," in each line, as the problem is that setgid in perl 5.34.1 ends up putting a -1 into $GID
and $EGID (which is 4294967295 as an unsigned 32-bit integer).

A sample macOS PLIST for /Library/LaunchDaemons (org.discord.reportnew.plist) is supplied for running as root with privilege separation (be sure to specify "privsep: yes" in
the config file, or alternatively add a -p option in the arguments list in the PLIST file); it can also run as an unprivileged user if
the only intent is to use it for process accounting log monitoring. (Use "launchctl load -w /Library/LaunchDaemons/org.discord.reportnew.plist" and it
will run every 30 minutes.)

Another sample macOS PLIST for /Library/LaunchDaemons (org.discord.rotateacct.plist) is supplied for rotating process accounting logs using the rotateacct.sh shell script.

Also included is a perl implementation of lastcomm.pl that works on OpenBSD, Linux, and macOS, but displays output chronologically (the order in the process accounting files) instead of in reverse chronological order.

Multiple hosts can be supported with a single config file using either
   hosts: <hostname-list>
to identify sections applicable to a set of space-separated hosts, or alternatively,
   begin-host: <hostname>
   ...
   end-host: <hostname>
to have a single unique section in the config file for each host. The former is preferred for compactness, simplicity, and eliminating redundancy between similarly-configured hosts.  reportnew -c can be used to check a config for possible syntax errors.

Actions can be "notify" (send email), "text" (send email with fewer
characters for SMS), "alert" (generate output to STDOUT), or "execute"
(pass matching log lines to a script). For "execute," privileges are
dropped and the script is executed as nobody:nogroup (or nobody group),
unless privilege separation is used in which case it is executed as
_reportnew:_reportnew. Scripts must be in a "scripts" subdirectory
under the config file directory and must be signify-signed using a
key defined in the config. If OpenBSD's OpenBSD::Pledge is updated
in the future to support execpromises, reportnew will be modified
to make use of it, but at present scripts are not bound by pledge
or unveil unless the script applies them itself.

An "execute" action can be added as a second action after any "notify,"
"text," or "alert" action by appending a semicolon to the end of the
first action and adding the execute action, e.g.,:

    action: notify foo@example.com; execute myscript.sh

This is intended for cases such as a script collecting data from a log
alert for some other purpose, e.g., for collecting malicious IPs or
host names, mail certificate fingerprints of connecting mail servers,
etc.

"frequency" in config file comments is not implemented; config file doesn't include an example of
the within-log correlation, here is an example used for alerting on an SMTP session of concern with
context for OpenSMTPD:

<PRE>
log: /var/log/maillog
match: session-with /[a-f0-9]{16} smtp/
exclude: session-without /([a-f0-9]{16}) smtp (?:failed-command|client-cert-check result="failure")/
action: notify <emailaddress>
</PRE>

This will start capturing logs when it matches a 16-character hex string followed by smtp, and then will
discard that collected set of logs unless it matches an smtp failed-command or smtp client-cert-check with
result=failure that uses that same 16-character hex string. If it does find the match, it reports the entire
collected context, including lines before and after the failures which contain the same hex string followed
by smtp.

The "match" field tells reportnew to collect matches of that string for later comparison, the "exclude"
field tells it to report on any of those collected log lines that have an envelope ID that matches the
regular expression capture group from a line with a failure.
  
---
  
To monitor process accounting logs to identify unusual activity from service accounts, normal users, or root, use something like the following:

<PRE>
  log: /var/account/acct
  match: all
  exclude: /(__|tty..) (_dovecot | _file | _identd | _ntp | _ping | _smtpd | _syspatch | _tcpdump | _traceroute | user1 | user2 | root | sshd | www)/
  action: notify myemailaddr
  
  match: /_dovecot/
  exclude: /anvil|auth|stats/
  action: notify myemailaddr
  
  match: /_file/
  exclude: /file/
  action: notify myemailaddr
  
  match: /_ntp/
  exclude: / ntpd/
  action: notify myemailaddr
  
  match: /_ping/
  exclude: / ping/
  action: notify myemailaddr
  
  match: /_smtpd/
  exclude: / mail.mboxf| sh | smtpctl | smtpd/
  action: notify myemailaddr
  
  match: /_syspatch/
  exclude: /ftp| sh | signify/
  action: notify myemailaddr
  
  match: /_tcpdump/
  exclude: / tcpdump/
  action: notify myemailddr
  
  match: /_traceroute/
  exclude: / traceroute/
  action: notify myemailaddr
  
  match: / user1/
  exclude: / list of commands | used by user1/
  action: notify myemailaddr
 </PRE>
  
and so on. The first set of directives will cause alerts for unknown users and the rest for unexpected activity by known users.

Quickstart for privilege separation support:
OpenBSD: pkg_add p5-IO-FDPass p5-Privileges-Drop p5-JSON-MaybeXS
Debian: apt-get install libio-fdpass-perl libprivileges-drop-perl libjson-maybexs-perl
FreeBSD: pkg install p5-IO-FDPass p5-Privileges-Drop p5-JSON-MaybeXS
CPAN: cpanm IO::FDPass Privileges::Drop JSON::MaybeXS

Create user _reportnew and group _reportnew

Set privsep: yes in reportnew.conf

Quickstart for process accounting support:
OpenBSD:
As root: touch /var/account/acct; accton
Verify with: lastcomm
Keeps 5 days by default, will rotate automatically

Debian:
As root: touch /var/log/account/pacct; accton
Verify with: lastcomm
Keeps 30 days by default, will rotate automatically.

On macOS:
As root (admin user, with sudo): sudo touch /var/account/acct; sudo accton
Install rotateacct.sh into /usr/local/bin
Install org.discord.reportnew.plist and org.discord.rotateacct.plist into /Library/LaunchDaemons
sudo launchctl load -w org.discord.reportnew.plist
sudo launchctl load -w org.discord.rotateacct.plist
Verify with: lastcomm (may require reboot)
Keeps forever and does not rotate by default, with org.discord.retateacct.plist, will
keep 5 days and rotate automatically.
(Requires postfix configuration for email delivery: minimal change is to update myhostname
and set relayhost in /etc/postfix/main.cf to send email off-host.)
