#!/usr/bin/perl

# Script to extract data about mail hosts with previously unseen fingerprints.
# Written 10 February 2026 by Jim Lippard.
# Modified 13 February 2026 by Jim Lippard to cache fingerprints and
#    macros.
# Modified 27 February 2026 by Jim Lippard to only log if it's a fingerprint
#    (and not already a substitute macro).

use strict;
use warnings;
use File::Basename qw( basename dirname );
use POSIX qw( strftime );
use Storable qw( lock_nstore lock_retrieve );
use Time::ParseDate;

use if $^O eq 'openbsd', 'OpenBSD::Pledge';
use if $^O eq 'openbsd', 'OpenBSD::Unveil';

my $CACHEFILE = '/etc/reportnew/scripts/logs/newcert.cache';
my $LOGFILE = '/etc/reportnew/scripts/logs/newcert.log';
my $ZONEINFO_DIR = '/usr/share/zoneinfo';

my (%date, %sender_ip, %sender_host, %recipient_host, %cert);
my ($uid, $domain_name);
my ($cacheref, %cache_cert, %cache_macro);

# Strictly limit access on OpenBSD.
if ($^O eq 'openbsd') {
    pledge ('rpath', 'wpath', 'cpath', 'flock', 'unveil') || die "Cannot pledge promises. $!\n";
    my $log_dir = dirname ($LOGFILE);
    unveil ($log_dir, 'rwc');
    unveil ($LOGFILE, 'rwc');
    unveil ($CACHEFILE, 'rwc');
    unveil ($ZONEINFO_DIR, 'r');
    unveil ();
}

# If cache file exists, read its contents.
if (-e $CACHEFILE && !-z $CACHEFILE) {
    $cacheref = lock_retrieve ($CACHEFILE);
    if (defined ($cacheref->{CERTS})) {
	%cache_cert = %{$cacheref->{CERTS}};
    }
    if (defined ($cacheref->{MACROS})) {
	%cache_macro = %{$cacheref->{MACROS}};
    }
}

while (<STDIN>) {
    if (/(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}) (\w+) smtpd\[\d+\]: ([0-9a-f]{16}) mta (.*$)/) {
	my $date_str = $1;
	my $host = $2;
	$uid = $3;
	my $rest = $4;
	if ($rest =~ /connecting address=smtp:\/\/(\d+\.\d+\.\d+\.\d+):25 host=(.*$)/) {
	    $date{$uid} = $date_str;
	    $recipient_host{$uid} = $host;
	    $sender_ip{$uid} = $1;
	    $sender_host{$uid} = $2;
	}
	elsif ($rest =~ /cert-check result.* fingerprint=\"(.*)\"/) {
	    $cert{$uid} = $1;
	}
    }
}

open (LOG, '>>', $LOGFILE) || die "Cannot open log file $LOGFILE. $!\n";

foreach $uid (keys (%date)) {
    if ($cert{$uid} =~ /SHA256:[0-9a-f]+/) {
	print LOG "$date{$uid}: $sender_ip{$uid} ($sender_host{$uid}): $cert{$uid}\n";
	# Is this new?
	if (!defined ($cache_cert{$cert{$uid}})) {
	    $cache_cert{$cert{$uid}} = 1;
	    # Build macro name.
	    my @domain_parts = split (/\./, $sender_host{$uid});
	    my $domain_tld = shift (@domain_parts);
	    $domain_name = shift (@domain_parts);
	    my $seconds = parsedate ($date{$uid});
	    my $isodate = strftime ("%F", localtime ($seconds));
	    $isodate =~ s/-//g;
	    if ($sender_host{$uid} =~ /e100\.net/) {
		$domain_name = 'google';
	    }
	    my $macro_name = 'CERT_' . $domain_name . '_' . $isodate;

	    if (defined ($cache_macro{$macro_name})) {
		$macro_name .= 'b';
	    }
	    $cache_macro{$macro_name} = 1;
	    print LOG "$macro_name = \"$cert{$uid}\":substitute\n";
	}
	else {
	    print LOG "$domain_name fingerprint $cert{$uid} still needs macro.\n";
	}
    }
}

close (LOG);

# Store cache.
my %cache = ( CERTS => \%cache_cert,
	       MACROS => \%cache_macro );
lock_nstore (\%cache, $CACHEFILE);

