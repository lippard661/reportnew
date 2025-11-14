# reportnew
Perl script to monitor logs for issues and issue alert emails, with some correlation capability within a log.

Supports syslog, cyclog, multilog, BSD (and macOS) and Linux process accounting logs, and Linux journal logs. Runs periodically rather than continuously.

Now uses and requires Signify.pm for signed include files.

Also available at https://www.discord.org/lippard/software

reportnew-1.25.tgz is a Legion of Dynamic Discord signify-signed OpenBSD package. Signify public key is https://www.discord.org/lippard/software/discord.org-2025-pkg.pub

Current version is reportnew-1.25 of 14 November 2025.

Multiple hosts can be supported with a single config file using either
   hosts: <hostname-list>
to identify sections applicable to a set of space-separated hosts, or alternatively,
   begin-host: <hostname>
   ...
   end-host: <hostname>
to have a single unique section in the config file for each host. The former is preferred for compactness, simplicity, and eliminating redundancy between similarly-configured hosts.  reportnew -c can be used to check a config for possible syntax errors.

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


