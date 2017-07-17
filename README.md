Installing PacketBL

Table of Contents:
	I.   Notes
	II.  Prerequisites
	III. Installation
	IV.  Configuration
	V.   Command Line Arguments


I. NOTES
	*NOTE* This document may very will be inaccurate, if at all possible
	you should refer to
		http://wiki.duskglow.com/index.php/Packetbl
	for authoritative information.

II. PREREQUISITES
	1. Dot.conf (required)
		Dot.conf is used to handle the configuration data and is
		required for PacketBL to operate.  It can be obtained from:
			http://www.azzit.de/dotconf/
		Dot.conf uses "Apache-style" configuration files so logical
		hierarchal configuration files can be used.

	2. iptables (required)
		Iptables' library "ipq" (IP Queuing library) is required, it
		provides the necessary hooks to allow PacketBL to accept
		packets from the QUEUE target and process them.

	3. FireDNS (optional)
		FireDNS is a library that queries all configured nameservers in
		parallel and once it gets an answer from one of them reports
		this.  It can make name resolution MUCH faster, especially when
		a configured nameserver is unreachable or down.

III. INSTALLATION
	1. PacketBL uses a GNU autoconf style `configure' script for
	   configuration.  To invoke this script run the `configure' script
	   within the top-level source directory, for example:
		./configure
	   There are a few options that can be passed to the `configure' script
	   that will affect the way PacketBL is built (in addition to the
	   standard autoconf `configure' script options):
		a. --with-cache
			This option will enable the experimental caching
			mechanism.  This may introduce unexpected problems.
			If you encounter any problems you should post a bug
			report to the PacketBL mailing list (for details, see
			http://lists.duskglow.com/packetbl).
		b. --with-firedns
			This option will cause PacketBL to use FireDNS's name
			resolution routines when testing IPs against DNS RBLs.
			Read above for more information on FireDNS.
		c. --with-stats
			This option will enable the experimental statistic
			gathering code, which will require an extra thread to
			handle incoming connections to a UNIX domain socket.
		d. --with-stats-socket=/path/to/socket
			This option allows one to specify the path to the UNIX
			domain socket that is used for communications between
			the PacketBL daemon and the "packetbl_getstat" process.
			Default is /tmp/.packetbl.sock.

IV. CONFIGURATION
	1. The configuration file (packetbl.conf) is in "Apache-style" format.
	   An example configuration file might look something like this:
		<host>
			BlackListBL     dnsbl.sorbs.net
			BlackListBL     relay.ordb.org
			WhiteList       127.0.0.0/8
		</host>
		FallthroughAccept      yes
		AllowNonPort25         no
		AllowNonSyn            no
		DryRun                 no
		CacheSize              8192
		CacheTTL               3600
		LogFacility            daemon
		Quiet                  no

	2. Explanation of configuration elements:
		a. <host>
			This element begins the HOST section of the
			configuration.  You must define your Blacklists DNS
			RBLs and Whitelist addresses in the HOST section.
		b. BlackListBL dnsbl.sorbs.net
			The "BlackListBL" element defines a DNS RBL which is
			checked to determine whether or not packets are
			dropped.  This particular example configures
			"dnsbl.sorbs.net" as an RBL to use.
		c. WhiteList 127.0.0.0/8
			The "WhiteList" element defines a range in (CIDR
			format) of IP address to always accept and never check
			the configured "BlackListBL" elements.  You should
			usually leave at least "127.0.0.0/8" there for safety.
		d. FallthroughAccept yes
			The "FallthroughAccept" element tells PacketBL how to
			handle packets that are neither listed in a configured
			DNS RBL ("BlackListBL" element) nor match a configured
			whitelist ("WhiteList" element).  Usually you should
			leave this as "yes" (the default).
		e. AllowNonPort25 no
			The "AllowNonPort25" element controls whether or not
			PacketBL will examine packets that are passed it that
			do not have a "Destination Port" of 25 (SMTP).  This
			is probably not something you want, leaving it "no"
			is safe.  Enabling this and mis-configuring your
			iptables configuration could cause a LOT of load on the
			configured DNS RBLs and may cause you to lose access to
			them!
		f. AllowNonSyn no
			The "AllowNonSyn" element controls whether or not
			PacketBL will examine packets that are passed it that
			do not have the SYN flag set (i.e, incoming TCP
			connections). This is probably not something you want,
			leaving it "no" is safe.  Enabling this and
			mis-configuring your iptables configuration could cause
			a LOT of load on the configured DNS RBLs and may cause
			you to lose access to them!
		g. DryRun no
			The "DryRun" element controls whether or not PacketBL
			actually rejects (DROPs) the packets that match a
			configured DNS RBL.  Setting this to "yes" will cause
			all packets to be ACCEPTed.  The default is "no"
			which causes normal operation.
		h. CacheSize 8192
			The "CacheSize" element determines the size of the
			cache (in entries, not bytes or bits) if cache has
			been enabled at compile time.  A setting of "0" causes
			caching to be disabled.  The largest reasonable value
			is currently 21675, anything above that will be wasted.
		i. CacheTTL 3600
			The "CacheTTL" element determines the length of time
			(in seconds) that cached entries are considered valid.
			Once an entry is looked up through a configured DNS RBL
			it will not need to be looked up again until after its
			"Time To Live" has been exceeded.
		j. LogFacility daemon
			The "LogFacility" element controls which syslog facility
			PacketBL sends its information to.  The default is
			probably fine for most people.
		k. Quiet no
			The "Quiet" element controls whether PacketBL writes
			a message to syslog() every time it accepts or rejects
			a packet.  The safe choice (and default) is "no"
			meaning that PacketBL writes a message to syslog about
			every packet.

V. COMMAND LINE ARGUMENTS
	1. PacketBL supports a minimal number of command line arguments, since
	   most configuration should be done in the configuration file (see
	   previous section).  The following is a complete list of supported
	   command line arguments:
		a. "-q"
			The "-q" option causes PacketBL to be quiet, it is
			identical to setting "Quiet" to "yes" in the
			configuration file.
		b. "-V"
			The "-V" option causes PacketBL to print out its
			version number and other relevant information to
			standard output and exit successfully.
	   Command line arguments always override their configuration file
	   counter-parts where appropriate.  Unknown command line arguments
	   cause PacketBL to terminate in error immediately at startup.
