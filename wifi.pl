#!/usr/bin/perl

# Script to extract data about WiFi SSIDs from Netgear WAX620 logs.
# Used with a reportnew rule that excludes known MAC/SSID combinations and
# sends everything else to this script; the resulting output log is monitored
# by reportnew.
# Modified from mailcert.pl.
# Written 20 February 2026 by Jim Lippard.

use strict;
use warnings;
use File::Basename qw( basename dirname );
use POSIX qw( strftime );
use Storable qw( lock_nstore lock_retrieve );
use Time::ParseDate;

use if $^O eq 'openbsd', 'OpenBSD::Pledge';
use if $^O eq 'openbsd', 'OpenBSD::Unveil';

my $CACHEFILE = '/etc/reportnew/scripts/logs/newwifi.cache';
my $LOGFILE = '/etc/reportnew/scripts/logs/newwifi.log';
my $ZONEINFO_DIR = '/usr/share/zoneinfo';

my (%date, %mac, %ssid, %band);
my $mac;
my ($cacheref, %cache_ssid, %cache_mac, %cache_band, %cache_date);

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
    if (defined ($cacheref->{SSIDS})) {
	%cache_ssid = %{$cacheref->{SSIDS}};
    }
    if (defined ($cacheref->{MACS})) {
	%cache_mac = %{$cacheref->{MACS}};
    }
    if (defined ($cacheref->{BANDS})) {
	%cache_band = %{$cacheref->{BANDS}};
    }
    if (defined ($cacheref->{DATES})) {
	%cache_date = %{$cacheref->{DATES}};
    }
}

while (<STDIN>) {
    if (/MAC: ([0-9a-f:]{17}).*?, SSID: (.*?), Channel: (\d+), Mode: (\d+), RSSI: (\d+), AP Type: (\d+), Timestamp: (.*?) , Epoch Timestamp: (\d+)/) {
	$mac = $1;
	my $ssid = $2;
	my $channel = $3; # distinguishes 2.4Ghz from 5Ghz
	my $mode = $4; # WiFi standard
	my $rssi = $5; # signal strength, lower means higher strength
	my $ap_type = $6;
	my $timestr = $7;
	my $time = $8;
	my $band;
	if ($channel <= 13) {
	    $band = 2.4;
	}
	elsif ($channel >= 36) {
	    $band = 5;
	}
	else {
	    $band = 'unknown';
	}
	# Modes: 23: 2.4GHz 802.11b/g/n in mixed mode
	#        31: 5 GHz 802.11a/n/ac/x

	$date{$mac} = $timestr;
	$ssid{$mac} = $ssid;
	$band{$mac} = $band;
    }
}

open (LOG, '>>', $LOGFILE) || die "Cannot open log file $LOGFILE. $!\n";

foreach $mac (keys (%date)) {
    if (!defined ($cache_date{$mac}) ||
	$cache_date{$mac} ne $date{$mac}) {
	print LOG "$date{$mac}: MAC: $mac, SSID: $ssid{$mac}, Band: $band{$mac}";
	# Is this new?
	if (!defined ($cache_mac{$mac})) {
	    $cache_mac{$mac} = 1;
	    $cache_ssid{$mac} = $ssid{$mac};
	    $cache_band{$mac} = $band{$mac};
	    $cache_date{$mac} = $date{$mac};
	    print LOG " (new)";
	}
	elsif ($cache_ssid{$mac} ne $ssid{$mac}) {
	    print LOG " (former SSID $cache_ssid{$mac})";
	}
	# Unnecessary if the log file is being read by reportnew and you use the default randomized MAC append macro.
	#print " (rand MAC)" if (substr ($mac, 1, 1) =~ /[26ae]/);
	print LOG "\n";
    }
}

close (LOG);

# Store cache.
my %cache = ( SSIDS => \%cache_ssid,
	      MACS => \%cache_mac,
	      BANDS => \%cache_band,
	      DATES => \%cache_date);
lock_nstore (\%cache, $CACHEFILE);

