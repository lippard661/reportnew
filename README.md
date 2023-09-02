# reportnew
Perl script to monitor logs for issues and issue alert emails, with some correlation capability within a log.

Supports syslog, cyclog, multilog, and BSD process accounting logs. Runs periodically rather than continuously.

Also available at https://www.discord.org/lippard/software

reportnew-1.14.tgz is a Legion of Dynamic Discord signify-signed OpenBSD package. Signify public key is https://www.discord.org/lippard/software/discord.org.pub

Current version is reportnew-1.14 of 2 September 2023.

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


