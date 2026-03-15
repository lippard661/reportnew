#!/usr/bin/perl

# Script to extract data about mail hosts with previously unseen fingerprints.
# Written 10 February 2026 by Jim Lippard.
# Modified 13 February 2026 by Jim Lippard to cache fingerprints and
#    macros.
# Modified 27 February 2026 by Jim Lippard to only log if it's a fingerprint
#    (and not already a substitute macro).
# Modified 12 March 2026 by Jim Lippard to build domain name for logging if
#    already cached.
# Modified 14 March 2026 by Claude: Added input sanitization, improved domain
#    extraction, better collision handling, stricter validation.

use strict;
use warnings;
use File::Basename qw( basename dirname );
use POSIX qw( strftime );
use Storable qw( lock_nstore lock_retrieve );
use Time::ParseDate;

# Optional: Use Domain::PublicSuffix for proper international domain handling
# https://metacpan.org/pod/Domain::PublicSuffix
# If not available, falls back to heuristic method below
my $HAVE_DOMAIN_PUBLICSUFFIX = 0;
eval {
    require Domain::PublicSuffix;
    $HAVE_DOMAIN_PUBLICSUFFIX = 1;
};

use if $^O eq 'openbsd', 'OpenBSD::Pledge';
use if $^O eq 'openbsd', 'OpenBSD::Unveil';

my $CACHEFILE = '/etc/reportnew/scripts/logs/newcert.cache';
my $LOGFILE = '/etc/reportnew/scripts/logs/newcert.log';
my $ZONEINFO_DIR = '/usr/share/zoneinfo';

my (%date, %sender_ip, %sender_host, %recipient_host, %cert);
my ($uid, $domain_name);
my ($cacheref, %cache_cert, %cache_macro);

# Known multi-part TLDs (incomplete list - Domain::PublicSuffix is better)
my %MULTI_PART_TLDS = (
    'co.uk' => 1, 'ac.uk' => 1, 'gov.uk' => 1, 'org.uk' => 1,
    'co.jp' => 1, 'ac.jp' => 1, 'go.jp' => 1, 'ne.jp' => 1,
    'com.au' => 1, 'net.au' => 1, 'org.au' => 1, 'edu.au' => 1,
    'co.nz' => 1, 'net.nz' => 1, 'org.nz' => 1,
    'com.br' => 1, 'net.br' => 1, 'org.br' => 1,
);

# Sanitize data for safe logging (prevent log injection)
sub sanitize_log_data {
    my ($data) = @_;
    return '' unless defined $data;
    $data =~ s/[\r\n]//g;           # Remove newlines
    $data =~ s/[^\x20-\x7E]/?/g;    # Replace non-printable with ?
    return $data;
}

# Extract registrable domain name from hostname
# Returns the part you'd register (e.g., "google" from mail.google.com)
sub extract_domain_name {
    my ($hostname) = @_;
    return 'unknown' unless defined $hostname && $hostname ne '';
    
    # If we have Domain::PublicSuffix, use it
    if ($HAVE_DOMAIN_PUBLICSUFFIX) {
        my $suffix = Domain::PublicSuffix->new();
        my $root = $suffix->get_root_domain($hostname);
        if (defined $root && $root =~ /^([^.]+)\./) {
            return $1;  # Return leftmost part of root domain
        }
    }
    
    # Fallback: Heuristic method
    my @parts = split(/\./, $hostname);
    
    # Handle single-part hostname
    return $parts[0] if (@parts == 1);
    
    # Check for multi-part TLD (e.g., co.uk)
    if (@parts >= 3) {
        my $potential_tld = $parts[-2] . '.' . $parts[-1];
        if ($MULTI_PART_TLDS{$potential_tld}) {
            # Return third-from-end: example.co.uk -> "example"
            return $parts[-3];
        }
    }
    
    # Default: return second-to-last component
    # mail.google.com -> "google"
    # smtp.gmail.com -> "gmail"
    return $parts[-2];
}

# Generate unique macro name with proper collision handling
sub generate_unique_macro {
    my ($base_name, $cache_ref) = @_;
    my $macro_name = $base_name;
    my $suffix = '';
    my $attempt = 0;
    
    while (defined $cache_ref->{$macro_name . $suffix}) {
        $attempt++;
        if ($attempt <= 26) {
            $suffix = chr(ord('a') + $attempt - 1);  # a, b, c, ...
        } else {
            $suffix = sprintf("%02d", $attempt - 26);  # 01, 02, 03, ...
        }
    }
    
    return $macro_name . $suffix;
}

# Strictly limit access on OpenBSD.
if ($^O eq 'openbsd') {
    pledge ('rpath', 'wpath', 'cpath', 'flock', 'unveil') || die "Cannot pledge promises. $!\n";
    my $log_dir = dirname ($LOGFILE);
    unveil ($log_dir, 'rwc');
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
    # Stricter fingerprint validation: SHA256 should be exactly 64 hex chars
    if ($cert{$uid} =~ /^SHA256:[0-9a-f]{64}$/) {
	# Sanitize all output data to prevent log injection
	my $safe_date = sanitize_log_data($date{$uid});
	my $safe_ip = sanitize_log_data($sender_ip{$uid});
	my $safe_host = sanitize_log_data($sender_host{$uid});
	my $safe_cert = sanitize_log_data($cert{$uid});
	
	print LOG "$safe_date: $safe_ip ($safe_host): $safe_cert\n";
	
	# Is this new?
	if (!defined ($cache_cert{$cert{$uid}})) {
	    $cache_cert{$cert{$uid}} = 1;
	    
	    # Extract proper domain name
	    $domain_name = extract_domain_name($sender_host{$uid});
	    
	    # Build macro name with date
	    my $seconds = parsedate ($date{$uid});
	    my $isodate = strftime ("%F", localtime ($seconds));
	    $isodate =~ s/-//g;
	    
	    my $base_macro = 'CERT_' . $domain_name . '_' . $isodate;
	    my $macro_name = generate_unique_macro($base_macro, \%cache_macro);
	    
	    $cache_macro{$macro_name} = 1;
	    print LOG "$macro_name = \"$safe_cert\":substitute\n";
	}
	else {
	    # Already cached - extract domain for logging
	    $domain_name = extract_domain_name($sender_host{$uid});
	    my $safe_domain = sanitize_log_data($domain_name);
	    print LOG "$safe_domain fingerprint $safe_cert still needs macro.\n";
	}
    }
    # Optionally log invalid fingerprints for debugging
    elsif (defined $cert{$uid} && $cert{$uid} =~ /SHA256:/) {
	my $safe_cert = sanitize_log_data($cert{$uid});
	print LOG "WARNING: Invalid fingerprint format: $safe_cert\n";
    }
}

close (LOG);

# Store cache.
my %cache = ( CERTS => \%cache_cert,
	       MACROS => \%cache_macro );
lock_nstore (\%cache, $CACHEFILE);
