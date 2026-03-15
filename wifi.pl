#!/usr/bin/perl

# Script to extract data about WiFi SSIDs from Netgear WAX620 logs.
# Used with a reportnew rule that excludes known MAC/SSID combinations and
# sends everything else to this script; the resulting output log is monitored
# by reportnew.
# Modified from mailcert.pl.
# Written 20 February 2026 by Jim Lippard.
# Modified 14 March 2026 by Claude: Added input sanitization, improved validation,
#    better channel classification.
# Modified 14 March 2026 by Jim Lippard to make randomized MAC reporting optional
#    and by Claude to fix bug in when randomized MAC reporting was occurring (was
#    only doing it for new MACs, not cached).

use strict;
use warnings;
use File::Basename qw( basename dirname );
use Storable qw( lock_nstore lock_retrieve );

use if $^O eq 'openbsd', 'OpenBSD::Pledge';
use if $^O eq 'openbsd', 'OpenBSD::Unveil';

my $CACHEFILE = '/etc/reportnew/scripts/logs/newwifi.cache';
my $LOGFILE = '/etc/reportnew/scripts/logs/newwifi.log';

# Cache pruning: Keep entries newer than this many seconds (7 days)
my $CACHE_MAX_AGE = 7 * 86400;  # 7 days * 86400 seconds/day

# Set to 1 if you want this logged; if using reportnew to monitor the
# output from this script if you have the default MAC_randomized append
# macro your reportnew output will automatically tag randomized MACs.
my $REPORT_RANDOMIZED_MACS = 0;

my (%epoch, %timestr, %ssid, %band);
my $mac;
my ($cacheref, %cache_ssid, %cache_mac, %cache_band, %cache_epoch);

# Sanitize data for safe logging (prevent log injection)
sub sanitize_log_data {
    my ($data) = @_;
    return '' unless defined $data;
    $data =~ s/[\r\n]//g;           # Remove newlines
    $data =~ s/[^\x20-\x7E]/?/g;    # Replace non-printable with ?
    return $data;
}

# Validate MAC address format
sub is_valid_mac {
    my ($mac) = @_;
    return 0 unless defined $mac;
    
    # Must be exactly 17 chars: XX:XX:XX:XX:XX:XX
    return 0 unless $mac =~ /^[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}$/i;
    
    # All zeros is invalid
    return 0 if $mac eq '00:00:00:00:00:00';
    
    # All FFs is broadcast address (invalid for AP)
    return 0 if $mac eq 'ff:ff:ff:ff:ff:ff';
    
    return 1;
}

# Check if MAC is randomized (locally administered)
# Bit 1 of first octet indicates locally administered address
sub is_randomized_mac {
    my ($mac) = @_;
    return 0 unless defined $mac && length($mac) >= 2;
    
    # Second character (first octet, low nibble)
    my $second_char = substr($mac, 1, 1);
    return ($second_char =~ /[26AaEe]/i);
}

# Classify WiFi band by channel number
sub classify_band {
    my ($channel) = @_;
    return 'unknown' unless defined $channel && $channel =~ /^\d+$/;
    
    # 2.4 GHz: Channels 1-14
    # Note: Channel 14 is only legal in Japan
    return '2.4' if ($channel >= 1 && $channel <= 14);
    
    # 5 GHz: Various UNII bands
    # UNII-1: 36-48
    # UNII-2: 52-64  
    # UNII-2 Extended: 100-144
    # UNII-3: 149-165
    return '5' if ($channel >= 36 && $channel <= 165);
    
    # 6 GHz (802.11ax): Channels 1-233
    # UNII-5: 1-93
    # UNII-6: 97-113
    # UNII-7: 117-185
    # UNII-8: 189-233
    # Note: Overlaps with 2.4GHz channel numbers, context needed
    # For now, mark as 6GHz if above 165
    return '6' if ($channel > 165 && $channel <= 233);
    
    return 'unknown';
}

# Strictly limit access on OpenBSD.
if ($^O eq 'openbsd') {
    pledge ('rpath', 'wpath', 'cpath', 'flock', 'unveil') || die "Cannot pledge promises. $!\n";
    my $log_dir = dirname ($LOGFILE);
    unveil ($log_dir, 'rwc');
    unveil ($CACHEFILE, 'rwc');
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
    if (defined ($cacheref->{EPOCHS})) {
	%cache_epoch = %{$cacheref->{EPOCHS}};
    }
    # Legacy support: if old cache has DATES instead of EPOCHS, ignore it
    # (next run will create new cache with epochs)
}

while (<STDIN>) {
    # Parse WiFi scan log entry
    # Note: SSID capture is non-greedy (.*?) to stop at first comma
    # MAC may have reportnew macro appended like: 22:ad:56:35:42:fa[MAC_randomized]
    if (/MAC: ([0-9a-f:]{17})(?:\[.*?\])?, SSID: (.*?), Channel: (\d+), Mode: (\d+), RSSI: (\d+), AP Type: (\d+), Timestamp: (.*?) , Epoch Timestamp: (\d+)/) {
	my $candidate_mac = lc($1);  # Normalize to lowercase
	my $raw_ssid = $2;
	my $channel = $3;
	my $mode = $4;           # WiFi standard (unused)
	my $rssi = $5;           # Signal strength (unused)
	my $ap_type = $6;        # AP type (unused)
	my $timestr = $7;        # Human-readable timestamp for logging
	my $epoch_time = $8;     # Epoch timestamp for comparisons/pruning
	
	# Validate MAC address
	next unless is_valid_mac($candidate_mac);
	
	$mac = $candidate_mac;
	
	# Classify band
	my $band = classify_band($channel);
	
	# Store in hashes (use MAC as key)
	# Store epoch (for comparison/pruning) and original timestr (for logging)
	$epoch{$mac} = $epoch_time;
	$timestr{$mac} = $timestr;
	$ssid{$mac} = $raw_ssid;
	$band{$mac} = $band;
    }
}

open (LOG, '>>', $LOGFILE) || die "Cannot open log file $LOGFILE. $!\n";

# Prune old entries from cache (older than CACHE_MAX_AGE)
my $now = time();
foreach my $old_mac (keys %cache_epoch) {
    if ($now - $cache_epoch{$old_mac} > $CACHE_MAX_AGE) {
	delete $cache_epoch{$old_mac};
	delete $cache_ssid{$old_mac};
	delete $cache_mac{$old_mac};
	delete $cache_band{$old_mac};
    }
}

foreach $mac (keys (%epoch)) {
    # Only log if new MAC or timestamp changed
    # (WAX620 repeats entries with same timestamp while AP still in range)
    if (!defined ($cache_epoch{$mac}) ||
	$cache_epoch{$mac} != $epoch{$mac}) {
	
	# Sanitize all output data
	my $safe_time = sanitize_log_data($timestr{$mac});
	my $safe_mac = sanitize_log_data($mac);
	my $safe_ssid = sanitize_log_data($ssid{$mac});
	my $safe_band = sanitize_log_data($band{$mac});
	
	print LOG "$safe_time: MAC: $safe_mac, SSID: $safe_ssid, Band: $safe_band";
	
	# Is this MAC new?
	if (!defined ($cache_mac{$mac})) {
	    $cache_mac{$mac} = 1;
	    $cache_ssid{$mac} = $ssid{$mac};
	    $cache_band{$mac} = $band{$mac};
	    $cache_epoch{$mac} = $epoch{$mac};
	    print LOG " (new)";
	}
	elsif ($cache_ssid{$mac} ne $ssid{$mac}) {
	    # SSID changed for known MAC
	    my $safe_old_ssid = sanitize_log_data($cache_ssid{$mac});
	    print LOG " (former SSID: $safe_old_ssid)";
	    
	    # Update cached SSID
	    $cache_ssid{$mac} = $ssid{$mac};
	}
	
	# Note if randomized MAC (check for all entries, not just new)
	if ($REPORT_RANDOMIZED_MACS && is_randomized_mac($mac)) {
	    print LOG " (randomized MAC)";
	}
	
	# Update cached epoch timestamp
	$cache_epoch{$mac} = $epoch{$mac};
	
	print LOG "\n";
    }
}

close (LOG);

# Store cache.
my %cache = ( SSIDS => \%cache_ssid,
	      MACS => \%cache_mac,
	      BANDS => \%cache_band,
	      EPOCHS => \%cache_epoch);
lock_nstore (\%cache, $CACHEFILE);
