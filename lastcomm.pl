#!/usr/bin/perl

# lastcomm-equivalent in perl that reports process accounting log
# contents in chronological order instead of reverse chronological
# order.

# Written 15 April 2024 by Jim Lippard after deciphering the 64-byte
# records of OpenBSD process accounting logs.
# Modified 20 December 2025 by Jim Lippard to work on Linux (acct v3)
#   to build devname_cache on OpenBSD instead of having it hardcoded,
#   and to use pledge and unveil on OpenBSD.

# Optional arguments to match user, device/tty, or command, multiple
# args treated as OR, not AND.

use strict;
use warnings;
use File::Find;
use Fcntl ':mode';
use File::Basename;
use Getopt::Std;
use POSIX qw( ctime fmod );
use if $^O eq 'openbsd', 'OpenBSD::Pledge';
use if $^O eq 'openbsd', 'OpenBSD::Unveil';

my $DEFAULT_LOG = '/var/account/acct'; # BSD
$DEFAULT_LOG = '/var/log/account/pacct' if ($^O eq 'linux');

my $AHZ = 64;
# from utmp.h UT_
my $UT_NAMESIZE = 32;
my $LINUX_UT_NAMESIZE = 8;
my $UT_LINESIZE = 8;

my $SECSPERHOUR = 60 * 60;
my $SECSPERMIN = 60;

my $COMMPIDSIZE = 24 + 13; # length of max $command + 13 for pid
my $LINUX_COMMPIDSIZE = 16; # no PID printed
my $MACOS_COMMPIDSIZE = 10; # no PID in process accounting

my $FLAGSIZE = 7;
my $LINUX_FLAGSIZE = 5;

my $OPENBSD_RECORD_FORMAT = "A24 S< S< S< S< q< L< L< L< l< L< b32";
my $LINUX_RECORD_FORMAT = "b8 C S< L< L< L< L< L< L< f< S< S< S< S< S< S< S< S< Z16";
my $MACOS_RECORD_FORMAT = "Z10 S< S< S< l< L< L< S< S< l< b8";
# OpenBSD and macOS using 64 bit btime, Linux using 32 bit btime

my $BSD_OUTPUT_FORMAT = "%-*.*s %-*.*s %-*.*s %-*.*s %6.2f secs %.16s";
my $LINUX_OUTPUT_FORMAT = "%-*.*s %*.*s %-*.*s %-*.*s %6.2f secs %.16s";

my @PROMISES = ('unveil', 'rpath', 'getpw');

my ($logfile, %opts);

my ($acctline, $command, $utime, $stime, $etime, $io, $btime, $uid, $gid,
    $mem, $tty, $pid, $flag);
my ($user, $commpid, $time, $delta, $tty_name);

my %devname_cache;

my ($output_format, $bsd_format, $linux_format); # output formats

# Get -f option if present.
# Add -b (bsd) and -l (linux) for output format.
getopts ('f:bl', \%opts) || die "Usage: lastcomm.pl [-f file] [command ...] [user ...] [terminal ...]\n";

$logfile = $opts{'f'} || $DEFAULT_LOG;

$bsd_format = $opts{'b'};
$linux_format = $opts{'l'};

die "-b and -l are mutually exclusive.\n" if ($bsd_format && $linux_format);

if ($linux_format) {
    $output_format = $LINUX_OUTPUT_FORMAT;
    $UT_NAMESIZE = $LINUX_UT_NAMESIZE;
    $COMMPIDSIZE = $LINUX_COMMPIDSIZE;
    $FLAGSIZE = $LINUX_FLAGSIZE; # could cause issues if > 5 flags
}
else { # default
    $bsd_format = 1;
    $output_format = $BSD_OUTPUT_FORMAT;
}

if ($^O eq 'darwin') {
    $UT_NAMESIZE = $LINUX_UT_NAMESIZE;
    $COMMPIDSIZE = $MACOS_COMMPIDSIZE;
    &build_devname_cache;
}

if ($^O eq 'openbsd') {
    &build_devname_cache;
    pledge (@PROMISES) || die "Could not pledge promises. $!\n";
    unveil ($logfile, 'r');
    unveil ();
}

open (ACCTLOG, '<', $logfile) || die "Cannot open accounting log $logfile. $!\n";
$/ = \64;
$/ = \40 if ($^O eq 'darwin');
while ($acctline = <ACCTLOG>) {
    if ($^O eq 'openbsd') {
	($command, $utime, $stime, $etime,
	 $io, $btime, $uid, $gid, $mem, $tty,
	 $pid, $flag) = unpack ($OPENBSD_RECORD_FORMAT, $acctline);
    }
    elsif ($^O eq 'darwin') {
	($command, $utime, $stime, $etime, $btime,
	 $uid, $gid, $mem, $io, $tty, $flag) = unpack ($MACOS_RECORD_FORMAT, $acctline);
	$pid = 0;
    }
    elsif ($^O eq 'linux') {
	my ($version, $exitcode, $ppid, $rw, $minflt, $majflt, $swaps); # unused
	($flag, $version, $tty, $exitcode, $uid, $gid, $pid,
	 $ppid, $btime, $etime, $utime, $stime, $mem, $io,
	 $rw, $minflt, $majflt, $swaps, $command) = unpack ($LINUX_RECORD_FORMAT, $acctline);
    }
    $user = getpwuid ($uid) || $uid;
    $commpid = "$command\[$pid\]";
    $commpid = $command if ($linux_format || $^O eq 'darwin');
    $time = &expand ($utime) + &expand ($stime);
    $delta = &expand ($etime) / $AHZ;
    $tty_name = &getdev ($tty);
    if ($#ARGV == -1 || &requested (@ARGV)) {
	printf "$output_format",
	    $COMMPIDSIZE, $COMMPIDSIZE, $commpid,
	    $FLAGSIZE, $FLAGSIZE, &flagbits ($flag),
	    $UT_NAMESIZE, $UT_NAMESIZE, $user,
	    $UT_LINESIZE, $UT_LINESIZE, $tty_name,
	    $time / $AHZ, ctime ($btime);
	printf " (%1.0f:%02.0f:%05.2f)",
	    $delta / $SECSPERHOUR,
	    fmod ($delta, $SECSPERHOUR) / $SECSPERMIN,
	    fmod ($delta, $SECSPERMIN) unless ($linux_format);
	print "\n";
    }
}

### Subroutines

# Subroutine to expand int16 time values.
sub expand {
    my ($time) = @_;
    my $newtime;

    $newtime = $time & 017777;
    $time >>= 13;
    while ($time) {
        $time--;
        $newtime <<= 3;
    }
    return ($newtime);
}

# Build devname cache (OpenBSD, macOS).
sub build_devname_cache {
    my $DEVDIR = '/dev';
    
    find (sub {
	return unless -c $_; # only character devices
	my $fullpath = $File::Find::name;
	my @st = lstat ($fullpath);
	my $rdev = $st[6]; # st_rdev
	$devname_cache{$rdev} ||= basename ($fullpath);
	  }, $DEVDIR);

    $devname_cache{-1} = '__';
}

# Linux device name decoding.
sub linux_device {
    my ($dev) = @_;
    my ($devname, $major, $minor);

    $major = ($dev >> 8) & 0xff;
    $minor = $dev & 0xff;

    if ($major == 4) {
	$devname = "tty$minor"; # virtual consoles
    }
    elsif ($major >= 136 && $minor <= 143) {
	my $pts = ($major - 136) * 256 + $minor;
	$devname = "pts/$pts"; # UNIX98 pts
    }
    elsif ($major == 5 && $minor == 1) {
	$devname = 'console'; # system console
    }
    elsif ($dev == 0) {
	$devname = '__';
    }
    else {
	$devname = "tty($major, $minor)"; # fallback
    }

    $devname_cache{$dev} = $devname;
    return $devname;
}

# Return device name from number.
sub getdev {
    my ($dev) = @_;
    my $dev_name;

    if (defined ($devname_cache{$dev})) {
	$dev_name = $devname_cache{$dev};
    }
    elsif ($^O eq 'linux') {
	$dev_name = &linux_device ($dev);
    }
    else {
	$dev_name = '??';
    }

    return ($dev_name);
}

# flags are defined in acct.h
# OpenBSD (32 bits)
# #define	AFORK	0x01		/* fork'd but not exec'd */
# #define	ASU	0x02		/* used super-user permissions */
# #define	AMAP	0x04		/* system call or stack mapping violation */
# #define	ACORE	0x08		/* dumped core */
# #define	AXSIG	0x10		/* killed by a signal */
# #define	APLEDGE	0x20		/* killed due to pledge violation */
# #define	ATRAP	0x40		/* memory access violation */
# #define	AUNVEIL	0x80		/* unveil access violation */
# Linux, macOS (8 bits)
# 104 #define AFORK       0x01    /* ... executed fork, but did not exec */
#  105 #define ASU     0x02    /* ... used super-user privileges */
#  106 #define ACOMPAT     0x04    /* ... used compatibility mode (VAX only not used) */
#  107 #define ACORE       0x08    /* ... dumped core */
#  108 #define AXSIG       0x10    /* ... was killed by a signal */
sub flagbits {
    my ($flag) = @_;
    my $output;
    my @flagbitmap = (
	[ 0, 'F' ], # fork'd but not exec'd
	[ 2, 'M' ], # killed by syscall or stack mapping violation
	[ 3, 'D' ], # dumped core
	[ 4, 'X' ], # killed by a signal
	[ 5, 'P' ], # killed due to pledge violation
	[ 6, 'T' ], # memory access violation
	[ 7, 'U' ], # unveil access violation
	[ 9, 'S' ], # killed by syscall pin violation
	[ 10, 'B' ] # BT CFI violation
	);
    @flagbitmap = (
	[ 0, 'F' ], # fork'd but not exec'd
	[ 1, 'S' ],
	[ 3, 'C' ],
	[ 4, 'X' ] # killed by a signal
	) if ($^O eq 'linux' || $^O eq 'darwin');

    $output = '-'; # OpenBSD-style, always a dash at start.
    $output = '' if ($linux_format);
    for my $bitmap_ent (@flagbitmap) {
	my ($idx, $ch) = @$bitmap_ent;
	$output .= $ch if (substr ($flag, $idx, 1) eq '1');
    }

    return $output;
}

sub requested {
    my (@match_args) = @_;
    my ($match_arg);

    foreach $match_arg (@match_args) {
	return 1 if ($match_arg eq $user ||
		     $match_arg eq $tty_name ||
		     $match_arg eq $command);
    }

    return 0;
}

sub flagbits_hex {
    my ($flags) = @_;
    my ($AFORK, $AMAP, $ACORE, $AXSIG,
	$APLEDGE, $ATRAP, $AUNVEIL, $APINSYS,
	$ABTCFI);
    my ($hexflags, $output);

    $hexflags = pack ("H32", $flags);
    
    vec ($AFORK, 0, 8) = 0x01;
#    vec ($ASU, 0, 8) = 0x02; (removed)
    vec ($AMAP, 0, 8) = 0x04;
    vec ($ACORE, 0, 8) = 0x08;
    vec ($AXSIG, 0, 8) = 0x10;
    vec ($APLEDGE, 0, 8) = 0x20;
    vec ($ATRAP, 0, 8) = 0x40;
    vec ($AUNVEIL, 0, 8) = 0x80;
    vec ($APINSYS, 0, 8) = 0x200;
    vec ($ABTCFI, 0, 8) = 0x400;

    $output = "-";
    $output .= "F" if ($hexflags & $AFORK);
    # etc.
    return ($output);
}

# OpenBSD process accounting log format in acct.h
# unpack template used above is:
# "A24 S< S< S< S< Q< L< L< L< l< L< b32"
# 64-byte records:
# A24: 24 characters, command
# S<: int16 user time
# S<: int16 system time
# S<: int16 elapsed time (cpu)
# S<: int16 I/O
# q<: 64 bit signed time
# L<: int32 uid
# L<: int32 gid
# L<: int32 mem
# l<: int32 signed $tty (-1 special case)
# L<: int32 pid (process ID)
# b32: 32-bit bit string of process flags

# macOS
#typedef u_short comp_t; /* 3 bits base 8 exponent, 13 bit fraction */
# Z10    char    ac_comm[10];    /* name of command (truncated to 9 chars + NULL) */
# S<    comp_t  ac_utime;     /* user time (units of 1/AHZ seconds) */
# S<    comp_t  ac_stime;     /* system time (units of 1/AHZ seconds) */
# S<    comp_t  ac_etime;     /* elapsed time (units of 1/AHZ seconds) */
# 32 bits l<    time_t  ac_btime;     /* starting time (seconds since epoch) */
# L<    uid_t   ac_uid;       /* user id */
# L<    gid_t   ac_gid;       /* group id */
# S<    short   ac_mem;       /* memory usage average (not well-supported) */
# S<    comp_t  ac_io;        /* count of IO blocks (not well-supported) */
# signed, -1 special l<    dev_t   ac_tty;       /* controlling tty */
# b8    char    ac_flag;      /* accounting flags (see below) */ (1 byte)
# and 3 bytes padding at end
