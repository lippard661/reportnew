# reportnew
Perl script to monitor logs for issues and issue alert emails, with some correlation capability within a log.

Supports syslog, cyclog, multilog, and BSD process accounting logs. Runs periodically rather than continuously.

Also available at https://www.discord.org/lippard/software

Current version is reportnew-1.13d of 10 March 2020.

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


