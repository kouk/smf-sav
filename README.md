smf-sav-reloaded 
================

Sender and receipient address verification by call ahead function.

smf-sav was originally written by Eugene Kurmanin, this version contains Gabriele Maria Plutzar's fixes (smf-sav-reloaded).

Original README from smf-sav-reloaded follows: 

Preamble: Fork of smf-sav project
=================================

As the original Author Eugene Kurmanin has no interest in this widely
used software any more, and didn't fix any bug, I, Gabriele Maria Plutzar
release a "reloaded" version with heavy bugfixes.
This version (smf-sav reloaded 2.0) should exactly do what you expect.

If you have bugfixes, or comments send them to smf-sav@anw.at. Perhaps
someone could test the IPV6 support, as I haven't done that yet.


About
=====
  It's a lightweight, fast and reliable Sendmail milter that implements
a real-time Sender e-Mail Address Verification technology. This technology
can stop some kinds of SPAM with a spoofed sender's e-Mail address.
  Also it implements a real-time Recipient e-Mail Address Verification
technology. It can be useful if your machine is a backup MX for the recipient's
domains or if your machine forwards all e-Mail messages as a relay host for your
domains to another internal or external e-Mail servers.
  It's a lite alternative for the spamilter, milter-sender and milter-ahead
milters.

  Features:

    - external editable configuration file;
    - whitelist by an IP address (in CIDR notation);
    - whitelist by a PTR (reverse DNS) record;
    - whitelist by an envelope sender e-Mail address;
    - whitelist by an envelope recipient e-Mail address;
    - scalable and tunable fast in-memory cache engine;
    - SMTP AUTH support;
    - strictly RFC-2821 compliant MX callback engine;
    - tolerance against non RFC-2821 compliant e-Mail servers;
    - blocking of e-Mail messages with a spoofed sender's e-Mail address;
    - recipient's e-Mail address verification with authoritative e-Mail stores;
    - progressive slowdown of recipient's e-Mail address brute force attacks;
    - Sendmail virtusertable and mailertable features full support.

Install
=======
  Requirements: Linux/FreeBSD/Solaris, Sendmail v8.11 and higher compiled with
the MILTER API support enabled, Sendmail Development Kit, POSIX threads library.
Under FreeBSD the BIND v8 is required (pkg_add -r bind).

  Edit the Makefile according to version of your Sendmail program and OS.

  Under the root account:
make
make install

  Inspect and edit the /etc/mail/smfs/smf-sav.conf file.

/usr/local/sbin/smf-sav
or
/usr/local/sbin/smf-sav -c /etc/mail/smfs/smf-sav.conf

  Add this milter to start-up scripts before starting a Sendmail daemon.
Look at the contributed samples of start-up scripts.

  Add these lines to your Sendmail configuration file (usually sendmail.mc):
define(`confMILTER_MACROS_HELO', confMILTER_MACROS_HELO`, {verify}')dnl
INPUT_MAIL_FILTER(`smf-sav', `S=unix:/var/run/smfs/smf-sav.sock, T=S:30s;R:4m')dnl

IMPORTANT: make sure that /var/run is not a group writable directory! If so,
or chmod 755 /var/run, or if it's impossible switch to another directory.

IMPORTANT: make sure that libmilter is compiled with BROKEN_PTHREAD_SLEEP defined.
If this symbol is not defined, libmilter will use sleep() in signal-handler thread,
which may cause various program misbehaviors, including coredumps.
To rebuild Sendmail with this symbol defined, add the following line to your
Sendmail/devtools/Site/site.config.m4:

  APPENDDEF(`confENVDEF', `-DBROKEN_PTHREAD_SLEEP')

If you are using the milter-greylist milter, please, bear in mind that it has an
incorrect proposition about the Sendmail macroses configuration. This one can
break the smf-sav milter functionality.

If you have the smf-zombie and smf-grey milters installed, the smf-sav milter
should be inserted after the smf-zombie milter and before the smf-grey milter.

If you want to have a highly improved and fully supported fusion of the smf-zombie,
smf-sav and smf-grey milters consider to acquire the milter-spamblocker milter.

Rebuild of your Sendmail configuration file and restart a Sendmail daemon.

  Under Linux add this line to your syslog.conf file and restart a Syslog daemon:
xxx.info	-/var/log/sav.log

  Under FreeBSD run this command: touch /var/log/sav.log
Then, add these lines to your syslog.conf file and restart a Syslog daemon:
!smf-sav
xxx.info	-/var/log/sav.log

Where xxx is a corresponded syslog facility from your smf-sav configuration
file.

If you want to exclude from logging the successfully verificated e-Mail addresses,
and cached records set the syslog priority to 'notice' instead 'info'. They
are just will be filtered out by a Syslog daemon.

Notes: The successfully authenticated senders will bypass all verification checks.
  Wildcard MX records with [square brackets] and standard MX records are fully
supported for the Sendmail mailertable feature.

It's very useful to add at your Sendmail configuration file these lines:

define(`confPRIVACY_FLAGS', `goaway,noetrn,nobodyreturn,noreceipts')dnl
define(`confTO_COMMAND', `1m')dnl
define(`confTO_IDENT', `0s')dnl
define(`confMAX_DAEMON_CHILDREN', `256')dnl enlarge if it's required
define(`confCONNECTION_RATE_THROTTLE', `8')dnl enlarge if it's required
define(`confBAD_RCPT_THROTTLE', `1')dnl Sendmail v8.12+
FEATURE(`greet_pause', `5000')dnl Sendmail v8.13+

Greetz Fly Out To
=================
  Jim Holland (Zimbabwe)
  Nikolaj Wicker (Germany)

TODO
====
  (maj) SAV policy switcher (reject/tag/quarantine) (v1.5.0);
  (maj) e-Mail messages Subject and header tagging (v1.5.0);
  (min) anti zombie hosts tricks and features (v1.6.0);
  (min) legitimate e-Mail messages friendly Greylisting technique (v1.7.0);
  (min) whitelists auto reloading (v1.8.0);
  (min) cache data dumping (v1.9.0);
  (min) cache data replication between multiple MX servers (v2.0.0);
  (?)   something else? just let me know.

(min) - minor priority;
(med) - medium priority;
(maj) - major priority.

  If you like this program, consider to purchase any of my commercial milters
from http://spamfree.ru/
  Thank you!

======================================
Become a sponsor for the SMFS project!
======================================

Any suggestions, support requests and bugs please send to <me@kurmanin.info>

Subscribe to SMFS announcements mailing list here:
  https://lists.sourceforge.net/lists/listinfo/smfs-list

Subscribe to SMFS users mailing list here:
  https://lists.sourceforge.net/lists/listinfo/smfs-users

SMFS development blog (opened for all):
  http://smfs.wordpress.com/

http://smfs.sourceforge.net/
http://sourceforge.net/projects/smfs/
http://kurmanin.info/
    
