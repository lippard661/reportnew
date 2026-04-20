# reportnew

A Perl script for periodic log monitoring and alerting. Monitors syslog
files, Linux journals, BSD/macOS/Linux process accounting logs, and
DJB-style cyclog/multilog logs for patterns of interest, sending email
alerts or executing signed scripts when matches are found.

Runs periodically (e.g., every 30 minutes via cron or launchd) rather than
continuously. Tracks log file positions between runs using a state file,
detects log rotation via a SHA256 hash of the first line, and handles
rotated and gzipped archive logs.

Primary platform is OpenBSD, with full support for Linux and macOS. Uses
pledge/unveil on OpenBSD. Supports privilege separation on all three
platforms using a `_reportnew` user and group.

Available at https://www.discord.org/lippard/software/ and
https://github.com/lippard661/reportnew

The OpenBSD package is signed with signify. To verify:
```
signify -C -p discord.org-2026-pkg.pub -x reportnew-<version>.tgz
```
Public key: https://www.discord.org/lippard/software/discord.org-2026-pkg.pub

## Features

- **Multiple log formats**: syslog files, Linux journals (by unit, syslog-id,
  or syslog-facility), BSD/macOS/Linux process accounting (binary format,
  no external tools required), and DJB cyclog/multilog
- **Match/exclude rules**: each log can have multiple match/exclude/action
  triplets; matches are Perl regular expressions
- **Macros**: define named regular expression fragments for reuse across
  rules; macros can be preproc (substituted into match/exclude patterns),
  postproc (appended to or substituted for matching text in output), or both
- **Signed macro include files**: macro definitions can be loaded from
  separate files, optionally requiring a signify signature; useful for
  keeping the main config immutable while allowing signed macro updates
- **Time constraints**: rules can be restricted to specific time windows
  using `define_time:` and `times:` directives, with negation support
- **Actions**: notify (email), text (minimal email for SMS), alert (stdout),
  or execute (pass matching lines to a signed script)
- **Combined actions**: any action can be followed by an execute action
  for simultaneous alerting and data collection
- **Session correlation**: `session-with`/`session-without` matching
  groups log lines by session ID and reports entire sessions only when
  a specified error pattern appears anywhere in the session
- **Multi-host configs**: a single config file can cover multiple hosts
  using `hosts:` directives to scope sections to specific hosts
- **Multiple configs**: multiple reportnew configs can run independently
  on the same host, each with its own state file; useful for different
  monitoring frequencies (e.g., 30-minute and daily configs)
- **Privilege separation**: privileged process handles file access;
  unprivileged `_reportnew` process does pattern matching and alerting
- **Signed execute scripts**: scripts invoked by execute actions must be
  in a `scripts/` subdirectory under the config directory and must be
  signed with the signify key defined in the config

## Process Accounting Monitoring

Process accounting logs record every command executed on the system.
reportnew parses the binary process accounting format directly on OpenBSD,
Linux, and macOS — no external tools required.

The recommended monitoring pattern is:

1. A rule matching all activity from unknown users (alerts on any unknown
   user running anything)
2. A rule matching core dump, pledge/unveil violation, or memory violation
   anomalies (OpenBSD-specific; has helped identify real security vulnerabilities)
3. Per-user rules matching everything and excluding the commands expected
   of that user — narrow for service accounts, broader for humans and root

The sample config includes extensive macro sets for expected commands by
user type on OpenBSD, Linux/Proxmox, and macOS, covering system daemons,
service accounts, and common user activity patterns.

Combined with `times:` constraints, process accounting monitoring can
alert on activity outside expected windows — for example, alerting on
SSH logins during sleeping hours, or on `_rsyncu` activity outside backup
windows.

## Session Correlation

The `session-with`/`session-without` feature groups log lines by session
ID and reports the entire group only when an error appears in it. This
provides full context for failures rather than just the error line.

Example for OpenSMTPD mail logs:
```
match: session-with /[a-f0-9]{16} (?:mta|smtp)/
exclude: session-without /([a-f0-9]{16}) (?:mta|smtp) (?:.*reject|fail|error|timeout)/
action: notify admin@example.com
```

The `session-with` pattern identifies lines belonging to the same session
(the capture group matches the session ID). The `session-without` pattern
identifies sessions to discard — any session that does NOT contain a
matching error line is discarded; sessions that DO contain an error are
reported in full including surrounding context lines.

## Time Constraints

Define named time windows and apply them to rules:

```
define_time: overnight = daily 22:00-06:00
define_time: backup_window = daily 02:00-04:00
define_time: reportnew_window = daily *:00-05, daily *:30-35

# Alert on SSH logins overnight
match: /sshd.*Accepted/
times: overnight
action: notify admin@example.com

# Alert on _rsyncu activity outside backup window
match: /_rsyncu /
times: !backup_window
action: notify admin@example.com

# Alert on _reportnew activity outside its own run window
match: /_reportnew /
times: !reportnew_window
action: notify admin@example.com
```

Time specification syntax:
```
daily                   Every day
Mon-Fri                 Day range
Mon,Wed,Fri             Specific days (no spaces)
all                     All day (00:00-23:59)
HH:MM-HH:MM             Time range (wraps midnight if end < start)
*:MM-MM                 Minute range of every hour
```

Multiple ranges can be combined with commas (OR logic).
Negate a constraint with `!`: `times: !business_hours`

## Configuration

The config file has three sections: global settings, macro definitions,
and log/rule definitions. The last argument to reportnew is always the
config file path.

**Global settings**:
```
master_notify: admin@example.com   # default notification address
size_file: /etc/reportnew/reportnew.size  # state file location
email_sender: nobody@example.com   # optional sender address
privsep: yes                        # use privilege separation
signify_pubkey: keyname.pub         # key for signed includes and scripts
```

**Macro definitions**:
```
# Preproc macro (substituted into match/exclude patterns as %%name%%)
known_hosts = "10\.0\.0\.1|10\.0\.0\.2"

# Postproc append macro (appended to matching output)
mac_addr = "ae:f0:b4:3b:83:a7":append

# Postproc substitute macro (replaces matching text in output)
ssh_pub_key = "AAAA...base64...":substitute

# Macro value from a file
known_fingerprints = "<file:fingerprints.txt>"

# Macro value from a signed file
known_fingerprints = "<signedfile:fingerprints.txt>"
```

Macro include files:
```
macro-include-file: shared-macros.conf
macro-include-signedfile: signed-macros.conf
```

**Log and rule definitions**:
```
log: /var/log/messages
match: /error|fail|reject/
exclude: /newsyslog.*logfile turned over/
action: notify admin@example.com

# With time constraint
match: /sshd.*Accepted/
times: overnight
action: notify admin@example.com

# Combined notify + execute
match: /cert-check result.*fingerprint/
exclude: /%%known_fingerprints%%/
action: notify admin@example.com; execute collect-certs.sh
```

**Journal log syntax** (Linux):
```
log: journal unit ssh.service
log: journal syslog-id doas
log: journal syslog-facility authpriv
```

**Multi-host scoping**:
```
hosts: host1 host2 host3
log: /var/log/messages
match: /error/
action: notify admin@example.com

hosts: host1
log: /var/log/authlog
match: /ROOT/
action: notify admin@example.com
```

Sections without a `hosts:` line apply to all hosts. The old
`begin-host:`/`end-host:` syntax is deprecated but still supported;
the two styles cannot be mixed.

## Actions

```
action: notify admin@example.com        # email full report
action: text admin@example.com          # email minimal (for SMS)
action: alert                            # output to STDOUT
action: execute script.pl               # pipe matching lines to signed script
action: notify admin@example.com; execute script.pl  # both
```
`notify` is the primary action for most use cases. `execute` is
particularly useful for automated data collection from alerts.
`alert` outputs to stdout and is mainly useful for manual testing;
-d (debug mode) is more practical for troubleshooting without config
changs. `text` sends a minimal email suitable for SMS gateways and may
be enhanced in a future version.

Execute scripts must be in a `scripts/` subdirectory under the config
file directory and must be signed with the key specified in `signify_pubkey`.
Scripts are executed as `_reportnew:_reportnew` (with privsep) or
`nobody:nogroup` (without). Scripts are not bound by pledge/unveil unless
they apply it themselves.

Two sample execute scripts are included:
- `mailcert.pl` — collects TLS certificate fingerprints from mail logs
  and generates macros for known certificates
- `wifi.pl` — collects WiFi SSIDs and MAC addresses from access point
  neighbor logs

## State File

reportnew maintains one state file covering all logs being monitored by
a given config. For each log it records the last processed offset and a
SHA256 hash of the first line at the time of last processing. On each
run it detects rotation (first line changed), truncation (file shorter
than last run), and new rotated/gzipped archive files, processing each
appropriately. The state file location is set by `size_file:` in the
config.

## Installation

### Recommended: OpenBSD signed package

```
pkg_add ./reportnew-<version>.tgz
```

Or using [install.pl](https://github.com/lippard661/distribute) on OpenBSD,
Linux, or macOS.

### Manual installation

```sh
cp src/reportnew.pl /usr/local/bin/reportnew
chmod 755 /usr/local/bin/reportnew
mkdir -p /etc/reportnew/scripts
cp etc/reportnew.conf /etc/reportnew/reportnew.conf
chmod 600 /etc/reportnew/reportnew.conf
```

### Dependencies

**Required**:
- Perl 5
- Standard modules: strict, warnings, Getopt::Std, Sys::Hostname,
  File::Basename, POSIX, Digest::SHA, Storable, File::Temp,
  IO::Uncompress::Gunzip

**For privilege separation** (recommended):
- IO::FDPass
- Privileges::Drop
- JSON::MaybeXS (preferred) or JSON::PP (standard, slower)

Install on OpenBSD: `pkg_add p5-IO-FDPass p5-Privileges-Drop p5-JSON-MaybeXS`
Install on Debian/Linux: `apt install libio-fdpass-perl libprivileges-drop-perl libjson-maybexs-perl`
Install via CPAN: `cpanm IO::FDPass Privileges::Drop JSON::MaybeXS`

Note: Privileges::Drop fails with the system Perl (5.34.1) on macOS Tahoe
26.1. Use Homebrew Perl (5.40.2+) or patch Privileges::Drop: on the lines
beginning with `my %GIDHash` and `my %EGIDHash`, insert
`grep { $_ != 4294967295 }` immediately before `split(/\s/,` in each line.
This works around a bug where setgid in Perl 5.34.1 puts -1 (0xFFFFFFFF
unsigned) into $GID and $EGID.

**For cyclog/multilog support**:
- Time::TAI64 (CPAN)

(Note: tai64nlocal from djb's daemontools was previously used but was
removed from OpenBSD ports due to licensing; Time::TAI64 provides the
same functionality.)

**For signed includes and execute scripts**:
- [Signify.pm](https://github.com/lippard661/Signify)
- signify (OpenBSD standard), signify-openbsd (Linux apt), or
  signify via Homebrew (macOS)

### Setting up privilege separation

```sh
# OpenBSD
useradd -r -d /var/empty -s /sbin/nologin _reportnew

# Linux
useradd -r -d /var/empty -s /usr/sbin/nologin _reportnew
```

Set `privsep: yes` in reportnew.conf.

### Setting up process accounting

**OpenBSD**:
```sh
touch /var/account/acct
accton
# Verify: lastcomm
# Rotates automatically, keeps 5 days by default
```

**Debian/Linux**:
```sh
apt install acct
touch /var/log/account/pacct
accton
# Verify: lastcomm
# Rotates automatically, keeps 30 days by default
```

**macOS**:
```sh
sudo touch /var/account/acct
sudo accton
# Install rotation and launch scripts from launchd/ directory:
sudo cp launchd/org.discord.accton.plist /Library/LaunchDaemons/
sudo cp launchd/org.discord.rotateacct.plist /Library/LaunchDaemons/
sudo cp src/rotateacct.sh /usr/local/bin/
sudo launchctl load -w /Library/LaunchDaemons/org.discord.accton.plist
sudo launchctl load -w /Library/LaunchDaemons/org.discord.rotateacct.plist
# Verify: lastcomm (may require reboot)
# Without rotateacct.plist, logs are never rotated.
# With it, keeps 5 days and rotates automatically.
```

### Scheduling on macOS

Three LaunchDaemon plists are provided in `launchd/`:
- `org.discord.accton.plist` — enable process accounting at boot
- `org.discord.reportnew.plist` — run reportnew every 30 minutes as root
  with privilege separation (ensure `privsep: yes` in config, or add `-p`
  to the plist arguments)
- `org.discord.rotateacct.plist` — rotate process accounting logs

```sh
sudo launchctl load -w /Library/LaunchDaemons/org.discord.reportnew.plist
```

reportnew can also run as an unprivileged user if only process accounting
monitoring is needed.

macOS requires a mail relay configuration for email delivery. Minimal
postfix configuration: set `myhostname` and `relayhost` in
`/etc/postfix/main.cf`.

### Scheduling on OpenBSD/Linux

Add to root's crontab:
```
*/30 * * * * /usr/local/bin/reportnew /etc/reportnew/reportnew.conf
```

Or with a randomized start within a window to reduce timing predictability:
```
0,30 * * * * sleep $((RANDOM \% 600)); /usr/local/bin/reportnew /etc/reportnew/reportnew.conf
```

## Command-Line Options

```
reportnew [options] configfile

-p          Use privilege separation
-c          Check config file for syntax errors and exit
-v          Verbose output
-d          Debug output
-V          Display version
```

## Security Notes

- `reportnew.conf` should be mode 0600 (root only); it reveals your
  monitoring rules and alert addresses. reportnew will warn if it finds
  the config world-readable.
- Macro include files that are not signed should also be protected;
  signed include files can be uchg-protected while the main config
  is schg-protected (see [syslock](https://github.com/lippard661/syslock))
- Execute scripts must be signify-signed; privileges are dropped before
  execution
- The state file (size_file) does not need to be tightly protected but
  should be root-owned; an attacker who can modify it could cause entries
  to be missed or re-reported, but cannot inject false alerts
- Running reportnew on both individual hosts and a central log server
  (receiving syslog via TLS with mutual certificate authentication)
  provides detection even if an individual host is compromised

## Extras

- `lastcomm.pl` — a Perl implementation of lastcomm that works on
  OpenBSD, Linux, and macOS, displaying output in chronological order
  (oldest first) rather than reverse chronological order. Supports
  output format options to match the native lastcomm on each platform.
  Written as a development aid for validating binary process accounting
  format parsing.

## Related Tools

- [syslock](https://github.com/lippard661/syslock) — manages immutability
  of log files (append-only live logs, immutable rotated logs) and config files
- [rsync-tools](https://github.com/lippard661/rsync-tools) — provides the
  _rsyncu user infrastructure monitored by reportnew
- [sigtree](https://github.com/lippard661/sigtree) — file integrity
  monitoring; reportnew can monitor sigtree's own activity via process
  accounting
- [distribute](https://github.com/lippard661/distribute) — uses rsync-tools
  infrastructure to sync signed reportnew macro include files across hosts
- [Signify](https://github.com/lippard661/Signify) — used for signed macro
  includes and execute script verification

## Author

Jim Lippard
https://www.discord.org/lippard/
https://github.com/lippard661

## License

See individual files for license information.

## Changelog

See docs/ChangeLog for detailed modification history.
