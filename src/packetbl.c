
/* Copyright 2004 Russell Miller
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "packetbl.h"
#include "directresolv.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <resolv.h>
#include <netdb.h>
#include <ctype.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <errno.h>
#include <linux/netfilter.h>

#include <dotconf.h>
#include <libpool.h>
#include <regex.h>

#ifdef USE_SOCKSTAT
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#endif

#ifdef HAVE_FIREDNS
#include <firedns.h>
#endif

#ifndef BUFFERSIZE
#define BUFFERSIZE 65536
#endif
#ifdef USE_CACHE
#  ifndef USE_CACHE_DEF_LEN
#    define USE_CACHE_DEF_LEN 8192
#  endif
#  ifndef USE_CACHE_DEF_TTL
#    define USE_CACHE_DEF_TTL 3600
#  endif
#endif

#  define TH_FIN        0x01
#  define TH_SYN        0x02
#  define TH_RST        0x04
#  define TH_PUSH       0x08
#  define TH_ACK        0x10
#  define TH_URG        0x20

# include <libnetfilter_queue.h>
# define SET_VERDICT nfq_set_verdict
# define PBL_HANDLE nfq_q_handle
# define PBL_SET_MODE nfq_set_mode
# define PBL_COPY_PACKET NFQNL_COPY_PACKET
# define PBL_ID_T u_int32_t
# define PBL_ERRSTR ""

# define CONFBUF 256

#define DEBUG(x, y) if (conf.debug >= x) { printf(y "\n"); }
struct packet_info {

	unsigned short int b1;
	unsigned short int b2;
	unsigned short int b3;
	unsigned short int b4;

	int s_port;
	int d_port;

	int flags;
};

struct cidr {

	uint32_t ip;
	uint32_t network;
	uint32_t processed;		/* network, but as a bitmask */

};

struct config_entry {

	char *string;
	struct config_entry *next;
	struct packet_info ip;
	struct cidr	cidr;

};

struct config_entry *blacklistbl = NULL;
struct config_entry *whitelistbl = NULL;
struct config_entry *blacklist = NULL;
struct config_entry *whitelist = NULL;

// to query to a alternative nameserver
static char alt_nameserver_file [CONFBUF];
static char alt_domain [CONFBUF];

struct bl_context {

	int	permissions;
	const char *current_end_token;

	pool_t *pool;
};

enum permissions {
	O_ROOT = 1,
	O_HOSTSECTION = 2,
	O_LAST = 4
};

static DOTCONF_CB(host_section_open);
static DOTCONF_CB(common_section_close);
static DOTCONF_CB(common_option);
static DOTCONF_CB(toggle_option);
static DOTCONF_CB(facility_option);

static const char *end_host = "</host>";
char msgbuf[BUFFERSIZE];

struct config {
	int	allow_non25;
	int	allow_nonsyn;
	int	default_accept;
	int	dryrun;
	int 	log_facility;
	int	queueno;
	int	quiet;
	char*	alt_resolv_file;
	char*	alt_domain;
	int	debug;
};
static struct config conf = { 0, 0, 1, 0, LOG_DAEMON, 0 };

static ldns_resolver *res = NULL;
// struct to save regexp of domain
static regex_t regex;

struct pbl_stat_info {
	uint32_t	cacheaccept;
	uint32_t	cachereject;
	uint32_t	whitelistblhits;
	uint32_t	blacklistblhits;
	uint32_t	whitelisthits;
	uint32_t	blacklisthits;
	uint32_t	fallthroughhits;
	uint32_t	totalpackets;
};
static struct pbl_stat_info statistics = { 0, 0, 0, 0, 0, 0, 0 };

#ifdef USE_CACHE
struct packet_cache_t {
	uint32_t ipaddr;
	time_t	expires;
	int	action;
};
struct packet_cache_t *packet_cache = NULL;
uint32_t packet_cache_len = USE_CACHE_DEF_LEN;
uint16_t packet_cache_ttl = USE_CACHE_DEF_TTL;
#endif

struct config_entry *hostlistcache = NULL;

int get_packet_info(char *payload, struct packet_info *ip);

int check_packet_list(const struct packet_info *ip, struct config_entry *list);
int check_packet_dnsbl(const struct packet_info *ip, struct config_entry *list);
int parse_cidr(struct config_entry *ce);
/* int validate_blacklist(char *); */
void parse_config(void);
void parse_arguments(int argc, char **argv);
void pbl_init_sockstat(void);
static void get_ip_string(const struct packet_info *ip);
static void pbl_set_verdict(struct PBL_HANDLE *h, PBL_ID_T id,
        unsigned int verdict);

static int pbl_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data);
	
static const configoption_t options[] = {
	{"<host>", ARG_NONE, host_section_open, NULL, O_ROOT},
	{"</host>", ARG_NONE, common_section_close, NULL, O_ROOT},
	{"blacklistbl", ARG_STR, common_option, NULL, O_HOSTSECTION},
	{"whitelistbl", ARG_STR, common_option, NULL, O_HOSTSECTION},
	{"whitelist", ARG_STR, common_option, NULL, O_HOSTSECTION},
	{"blacklist", ARG_STR, common_option, NULL, O_HOSTSECTION},
	{"fallthroughaccept", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"allownonport25", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"allownonsyn", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"dryrun", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"quiet", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"alternativedomain", ARG_STR, toggle_option, NULL, O_ROOT},
	{"alternativeresolvefile", ARG_STR, toggle_option, NULL, O_ROOT},
#ifdef USE_CACHE
	{"cachettl", ARG_INT, toggle_option, NULL, O_ROOT},
	{"cachesize", ARG_INT, toggle_option, NULL, O_ROOT},
#endif
	{"logfacility", ARG_STR, facility_option, NULL, O_ROOT},
#ifdef HAVE_NFQUEUE
	{"queueno", ARG_INT, common_option, NULL, O_ROOT},
#endif
	LAST_OPTION
};

FUNC_ERRORHANDLER(error_handler) {

	fprintf(stderr, "[error] %s\n", msg);
	return 1;

}

/*
 * SYNOPSIS:
 *   void daeomize(void);
 *
 * NOTES:
 *   This function accomplishes everything needed to become a daemon.
 *   Including closing standard in/out/err and forking.
 *   It returns nothing, on failure the program must abort.
 *
 */
void daemonize(void) {

	pid_t pid;

	chdir("/");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	setsid();

	pid = fork();

	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}
	if (pid < 0) {
		if (conf.debug == 0) {
			syslog(LOG_ERR, "Fork failed while daemonizing: %s",
				strerror(errno));
		} else {
			fprintf(stderr, "Fork failed while daemonizing: %s",
				strerror(errno));
		}
		exit(EXIT_FAILURE);
	}

}

#ifdef USE_CACHE
/*
 * SYNOPSIS:
 *   static uint32_t packet_cache_hash(
 *                                     const struct packet_info ip
 *                                    );
 *
 * ARGUMENTS:
 *   struct packet_info ip        Structure containing information about the
 *                                IP address to create the hash.
 *
 * RETURN VALUE:
 *   An integer representing the hash value is returned.  This value *MAY BE*
 *   greater than the size of the hash table, so it should be checked before
 *   use.
 *
 * NOTES:
 *
 * CURRENT IMPLEMENTATION NOTES (do not rely on this for design):
 *   Currently, only the IP portion of the structure is used for computing the
 *   hash.
 *   The current implementation will never return a value greater than 21675
 *   so having a hash table larger than that would be wasteful.
 *
 */
static uint32_t packet_cache_hash(const struct packet_info ip) {
	uint32_t hash = 0;

	hash = ip.b1 << 6;
	hash += ip.b2 << 4;
	hash += ip.b3 << 2;
	hash += ip.b4;
	return hash;
}


/*
 * SYNOPSIS:
 *   void packet_cache_clear(void);
 *
 * ARGUMENTS:
 *   (none)
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 *   This function must succeed even if "packet_cache" is NULL.
 *   This function initializes the values inside the previously allocated
 *   "packet_cache" array to safe values so that we may check entries
 *   safely.
 *
 */
void packet_cache_clear(void) {
	uint32_t i;

	if (packet_cache==NULL) return;

	for (i=0; i<packet_cache_len; i++) {
		packet_cache[i].ipaddr = 0;
		packet_cache[i].action = NF_ACCEPT;
		packet_cache[i].expires = 0;
	}

	return;
}
#endif

/*
 * SYNOPSIS:
 *   static uint32_t packet_info_to_ip(
 *                                     const struct packet_info ip
 *                                    );
 *
 * ARGUMENTS:
 *   struct packet_info ip        Structure containing IP fields to convert to
 *                                a 32bit unsigned integer.
 *
 * RETURN VALUE:
 *   This function returns a 32bit unsigned integer that represents a
 *   "one-to-one" mapping of IP octets and integer addresses, it will not
 *   overlap, therefore.
 *
 * NOTES:
 *
 */
static uint32_t packet_info_to_ip(const struct packet_info ip) {
	return ((ip.b1 & 0xff) << 24) | 
		((ip.b2 & 0xff) << 16) | 
		((ip.b3 & 0xff) << 8) | 
		(ip.b4 & 0xff);
}

/*
 * SYNOPSIS:
 *   int packet_check_ip(
 *                       const struct packet_info ip
 *                      );
 *
 * ARGUMENTS:
 *   struct packet_info ip        Structure containing information about
 *                                packet to check.
 *
 * RETURN VALUE:
 *   "packet_check_ip" returns an action to supply to "pbl_set_verdict".
 *   Currently, it will be one of NF_DROP or NF_ACCEPT but other values should
 *   be accounted for.  The supplied information is checked against the
 *   configued DNS RBLs and Whitelists to determine the appropriate action.
 *
 * NOTES:
 *   This function may return stale entries due to caching.
 *   This function MUST continue to work if "packet_cache" is NULL.
 *
 */
int packet_check_ip(const struct packet_info ip) {
	int retval;

#ifdef USE_CACHE
	uint32_t ipaddr_check;
	uint32_t cache_hash = 0;
	time_t currtime;
	char *actionstr;

	currtime = time(NULL);

	ipaddr_check = packet_info_to_ip(ip);
	if (packet_cache_len > 0) {
		cache_hash = packet_cache_hash(ip) % packet_cache_len;
	}

	if (cache_hash>0 && cache_hash<packet_cache_len && packet_cache != NULL) {
		if (packet_cache[cache_hash].ipaddr==ipaddr_check 
				&& packet_cache[cache_hash].expires>currtime) {
			get_ip_string(&ip);
			retval = packet_cache[cache_hash].action;
			switch (retval) {
				case NF_DROP:
					actionstr="reject";
					statistics.cachereject++;
					break;
				case NF_ACCEPT:
					actionstr="accept";
					statistics.cacheaccept++;
					break;
				default:
					actionstr="???";
					break;
			}
			if (!conf.quiet) {
				if (conf.debug == 0) {
					syslog(LOG_INFO, "[Found in cache (%s)] [%s]",
						actionstr, msgbuf);
				} else {
					fprintf(stderr, "[Found in cache (%s)] [%s]",
						actionstr, msgbuf);
				}
			}
			return retval;
		}
	}
#endif

	/* the get_ip_string is set AFTER the check_packet_*
	 * calls because of the possibility they could screw with
	 * msgbuf.  They shouldn't, really, but better safe than
	 * sorry, at least for now. */
	if (check_packet_list(&ip, whitelist) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet) {
			if (conf.debug == 0) {
				syslog(LOG_INFO,
					"[accept whitelist] [%s]",
						msgbuf);
			} else {
				fprintf(stderr,
					"[accept whitelist] [%s]",
						msgbuf);
			}
		}
		statistics.whitelisthits++;
		retval=NF_ACCEPT;
	} else
	if (check_packet_list(&ip, blacklist) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet) {
			if (conf.debug == 0) {
				syslog(LOG_INFO,
					"[reject blacklist] [%s]",
						msgbuf);
			} else {
				fprintf(stderr,
					"[reject blacklist] [%s]",
						msgbuf);
			}
				
		}
		statistics.blacklisthits++;
		retval=NF_DROP;
	} else
	if (check_packet_dnsbl(&ip, whitelistbl) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet) {
			if (conf.debug == 0) {
				syslog(LOG_INFO,
					"[accept dnsbl] [%s]",
						msgbuf);
			} else {
				fprintf(stderr,
					"[accept dnsbl] [%s]",
						msgbuf);
			}
		}
		statistics.whitelistblhits++;
		retval=NF_ACCEPT;
	} else
	if (check_packet_dnsbl(&ip, blacklistbl) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet) {
			if (conf.debug == 0) {
				syslog(LOG_INFO,
					"[reject dnsbl] [%s]",
						msgbuf);
			} else {
				fprintf(stderr,
					"[reject dnsbl] [%s]",
						msgbuf);
			}
		}
		statistics.blacklistblhits++;
		retval=NF_DROP;
	} else {
		get_ip_string(&ip);
		if (conf.default_accept == 1) {
			if (!conf.quiet) {
				if (conf.debug == 0) {
					syslog(LOG_INFO,
						"[accept fallthrough] [%s]",
							msgbuf);
				} else {
					fprintf(stderr,
						"[accept fallthrough] [%s]",
							msgbuf);
				}
			}
			retval=NF_ACCEPT;
		} else {
			if (!conf.quiet) {
				if (conf.debug == 0) {
					syslog(LOG_INFO,
						"[reject fallthrough] [%s]",
							msgbuf);
				} else {
					fprintf(stderr,
						"[reject fallthrough] [%s]",
							msgbuf);
				}

			}
			retval=NF_DROP;
		}
		statistics.fallthroughhits++;
	}

#ifdef USE_CACHE
	/* Put current action into the cache. */
	if (packet_cache != NULL) {
		packet_cache[cache_hash].ipaddr = ipaddr_check;
		packet_cache[cache_hash].action = retval;
		packet_cache[cache_hash].expires = currtime + packet_cache_ttl;
	}
#endif

	return retval;
}

static int pbl_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
        struct nfq_data *nfa, void *data) {

	int ret;
	int id;
	struct nfqnl_msg_packet_hdr *ph;
#if NETFILTERQUEUE_VERSION_NUMBER == 0
	char *nfdata;
#else
	unsigned char *nfdata;
#endif
	struct packet_info ip;

	DEBUG(2, "Entering callback");

	if (ph = nfq_get_msg_packet_hdr(nfa)) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &nfdata);
	/* what return codes here? */

	ret = get_packet_info(nfdata, &ip);	
	if (ret == -1) {
		pbl_set_verdict(qh, id, NF_ACCEPT);
		return;
	}

	ret = packet_check_ip(ip);
	
	if (conf.debug >= 2) {
	printf ("Got packet from %hhu.%hhu.%hhu.%hhu: %d\n", ip.b1, ip.b2, ip.b3, ip.b4, ret);
	}
	pbl_set_verdict(qh, id, ret);
}
/*
 * SYNOPSIS:
 *   static void pbl_set_verdict(
 *                               const struct PBL_HANDLE *h,
 *                               ipq_id_t id,
 *                               unsigned int verdict
 *                              );
 *
 * ARGUMENTS:
 *   struct PBL_HANDLE *h         IP Queue handle, must not be NULL
 *   ipq_id_t id                  XXX: Id ???
 *   unsigned int verdict         Verdict to assign this packet in the queue.
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 *   This function calls ipq_set_verdict() to the appropriate "verdict"
 *   It must be able to handle the condition where "conf.dryrun" is set
 *   causing all "verdict" values to be treated as NF_ACCEPT regardless
 *   of their actual value.
 *
 */
static void pbl_set_verdict(struct PBL_HANDLE *h, PBL_ID_T id,
	unsigned int verdict) {

	if (conf.dryrun == 1) {
		SET_VERDICT(h, id, NF_ACCEPT, 0, NULL);
	} else {
		SET_VERDICT(h, id, verdict, 0, NULL);
	}
}

/*
 * SYNOPSIS:
 *   int main(
 *            int argc,
 *            char **argv
 *           );
 *
 * ARGUMENTS:
 *   int argc                     "Argument Count," number of valid elements
 *                                in the "argv" array too.
 *   char **argv                  "Argument Vector," array of pointers to the
 *                                arguments passed to this process.
 *
 * RETURN VALUE:
 *   This function should never return, since we are a daemon.  The parent
 *   process exits with success (EXIT_SUCCESS) from daemonize();
 *
 * NOTES:
 *   This is the function that should be called before any others, it does
 *   many important initialization routines (reading configuration file,
 *   setting up the IP Queue routines, system logging, etc) and provides
 *   the main loop where packets are read and processed.
 *
 */
int main(int argc, char **argv) {

	struct PBL_HANDLE *handle;
	char buf[BUFFERSIZE];
	struct nfq_handle *h;
	struct nfnl_handle *nh;
	int fd;
	struct packet_info ip;
	struct stat fbuf;
	int action;
	int rv;

	conf.debug = 0;

	if (stat("/proc/net/netfilter/nfnetlink_queue", &fbuf) == ENOENT) {
		fprintf(stderr, "Please make sure you have\ncompiled a kernel with the Netfilter QUEUE target built in, or loaded the appropriate module.\n");
		exit(EXIT_FAILURE);
	}

	/* Parse our configuration data. */
	parse_config();


	/* We parse arguments after parsing the config file so we can override the
	   config file. */
	parse_arguments(argc, argv);

	if (conf.debug > 0) {
		fprintf(stderr, "Debug level %d\n", conf.debug);
	}

	if (conf.debug > 0) {
		fprintf(stderr, "Linking to queue %d\n", conf.queueno);
	}

	openlog("packetbl", LOG_PID, conf.log_facility);
	if (conf.debug == 0) {
		daemonize();
	}

#ifdef USE_SOCKSTAT
	pbl_init_sockstat();
#endif

#ifdef USE_CACHE
	if (packet_cache_len > 0) {
		/* Allocate space for the packet cache if a positive number of
		   elements is requested. */
		packet_cache = malloc(sizeof(*packet_cache) * packet_cache_len);
	} else {
		packet_cache = NULL;
	}

	packet_cache_clear();
#endif

	// Creating alternative nameservers to do request directly to zevenet domain
	
		//~ syslog(LOG_ERR, "Domain: %s",conf.alt_domain);
		//~ syslog(LOG_ERR, "nameserver file: %s",conf.alt_resolv_file);
	if ((configure_direct_nameserver( &res, conf.alt_resolv_file )) == -1) {
		syslog(LOG_ERR, "Load nameservers failed");
		DEBUG(1, "configure_direct_nameserver error");
		exit(EXIT_FAILURE);
	}
	if (res==NULL)
	{
		DEBUG(2, "Optional nameservers has not been saved");
		exit(EXIT_FAILURE);
	}
	
	if (conf.log_facility)
	{
		// creating regexp to compare request domain with a specific domain
		if ( regcomp(&regex, conf.alt_domain, 0) != 0 )
		{
			syslog(LOG_ERR, "Create regexp failed");
			exit(EXIT_FAILURE);
		}
	}
	
	// initializing nfqueue
	DEBUG(2, "Creating nfq handle...");
	if ((h = nfq_open()) == NULL) {
		syslog(LOG_ERR, "Couldn't create nfq handle: %s", strerror(errno));
		DEBUG(1, "Couldn't create nfq handle");
		exit(EXIT_FAILURE);
	}
	DEBUG(2, "unbinding nfq handle...");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		syslog(LOG_ERR, "Couldn't unbind nf_queue handler for AF_INET");
		DEBUG(1, "Couldn't unbind nf_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	DEBUG(2, "binding nfq handle...");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		syslog(LOG_ERR, "Couldn't bind ns_queue handler for AF_INET");
		DEBUG(1, "Couldn't bind ns_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	DEBUG(2, "creating queue...");
	if ((handle = nfq_create_queue(h, conf.queueno, &pbl_callback, NULL)) == NULL) {
		syslog(LOG_ERR, "nfq_create_queue failed");
		DEBUG(1, "nfq_create_queue failed");
		exit(EXIT_FAILURE);
	}

	if ((PBL_SET_MODE(handle, PBL_COPY_PACKET, BUFFERSIZE)) == -1) {
		syslog(LOG_ERR, "ipq_set_mode error: %s", PBL_ERRSTR);
		DEBUG(1, "ipq_set_mode error");
		if (errno == 111) {
			syslog(LOG_ERR, "try loading the ip_queue module");
		}
		exit(EXIT_FAILURE);
	}

	syslog(LOG_INFO, "packetbl started successfully");
	DEBUG(1, "packetbl started successfully");

	/* main packet processing loop.  This loop should never terminate
	 * unless a signal is received or some other unforeseen thing
	 * happens.
	 */
	while (1) {

		nh = nfq_nfnlh(h);
		fd = nfnl_fd(nh);
		DEBUG(2, "Entering main loop.");

		DEBUG(2, "waiting for a packet...");
		while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0) {
			DEBUG(2, "Handling a packet");
			nfq_handle_packet(h, buf, rv);
		}
		DEBUG(2, "Packet got.");
		statistics.totalpackets++;

	}
}

/*
 * SYNOPSIS:
 *   int get_packet_info(
 *                       ipq_packet_msg_t *packet,
 *                       struct packet_info *ip
 *                      );
 *
 * ARGUMENTS:
 *  ipq_packet_msg_t *packet      IP Queue supplied packet headers
 *  struct packet_info *ip        Structure to be filled in.
 *
 * RETURN VALUE:
 *   0 is returned on success, non-zero indicates that the packet could not
 *   be properly processed (i.e., it's off the wrong protocol or version).
 *
 * NOTES:
 *   This function fills in the previously allocated "ip" parameter with
 *   data from the "packet" parameter.
 *
 */
int get_packet_info(char *payload, struct packet_info *ip) {

	int version;
	int ip_header_length, header_size;;

	if (ip == NULL || payload == NULL) {
		return -1;
	}

	ip->s_port = 0;
	ip->d_port = 0;

	/* Get IP Version		Byte 1 of IP Header */
	version = payload[0] & 0xF0;
	version >>= 4;
	/* Get IP Header length		Byte 2 of IP Header
	 * Header length is usually 20, or 5 32-bit words */
	ip_header_length = payload[0] & 0x0F;
	header_size = ip_header_length * 4;

	/* We're not handling IPV6 packets yet.  I'll probably rewrite
	 * this whole damned thing in C++ first. */
	if (version != 4) {
		return -1;
	}

	/* IP Address			Bytes 13 - 16 of IP header */
	ip->b1 = payload[12];
	ip->b2 = payload[13];
	ip->b3 = payload[14];
	ip->b4 = payload[15];

	/* Source Port			Bytes 21 - 22 of IP Header
	 *				Bytes 1 - 2 of TCP Header */
	ip->s_port = payload[header_size] * 256;
	ip->s_port += payload[header_size + 1];

	/* Destination Port		Bytes 23 - 24 of IP Header
	 *				Bytes 3 - 4 of TCP Header */
	ip->d_port = payload[header_size + 2] * 256;
	ip->d_port += payload[header_size + 3];

	/* TCP Flags			Byte 14 of TCP header
	 *				Last six bits
	 * We're only interested at present in the SYN Flag.
	 * But there's no reason not to copy all of them, the operation
	 * would take pretty much the same time anyway. */
	ip->flags = payload[header_size + 13] & 0x3F;

	/* Returning -1, at present accepts the packet unconditionally. */
	if (conf.allow_non25 == 0 && ip->d_port != 25) {
		return -1;
	}

	if ((conf.allow_nonsyn == 0) && ((ip->flags & TH_SYN) == 0)) {
		return -1;
	}

	/* Return success */
	return 0;
}
/*
 * SYNOPSIS:
 *   void parse_config(void);
 *
 * ARGUMENTS:
 *   (none)
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 *   This function parses the configuration file and sets the appropriate
 *   global variables.  It may cause the program to abort with a failure
 *   if the configuration is unreadable or unparsable.  Due to this fact,
 *   it should only be called during start-up and not from the main loop.
 *
 */
void parse_config(void) {

	configfile_t *configfile;
	struct bl_context context;

	context.pool = pool_new(NULL);
	configfile = dotconf_create(CONFIGFILE, options, (void *)&context,
		CASE_INSENSITIVE);
	if (!configfile) {
		fprintf(stderr, "Error opening config file\n");
		exit(EXIT_FAILURE);
	}
	if (dotconf_command_loop(configfile) == 0) {
		fprintf(stderr, "Error reading configuration file\n");
		exit(EXIT_FAILURE);
	}

	dotconf_cleanup(configfile);
	pool_free(context.pool);

	return;
}
/*
 * SYNOPSIS:
 *   void parse_arguments(
 *                        int argc,
 *                        char **argv
 *                       );
 *
 * ARGUMENTS:
 *   int argc                     "Argument Count," number of valid elements
 *                                in the "argv" array too.
 *   char **argv                  "Argument Vector," array of pointers to the
 *                                arguments to be considered for processing.
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 *   Use getopt() to parse passed short arguments.  This should be done after
 *   parsing the config file, because we might need to override some of its
 *   settings.  We cannot return sucess or failure, so upon failure we should
 *   abort the program.
 *
 */
void parse_arguments(int argc, char **argv) {
	int ch;

	while ((ch = getopt(argc, argv, "qVd")) != -1) {
		switch (ch) {
			case 'q':
				conf.quiet = 1;
				break;
			case 'V':
				printf("PacketBL version %s\n", PACKAGE_VERSION);
				exit(EXIT_SUCCESS);
				break;
			case 'd':
				conf.debug++;
				break;
			case '?':
			case ':':
			default:
				exit(EXIT_FAILURE);
				break;
		}
	}

	return;
}

DOTCONF_CB(common_section_close) {

	struct bl_context *context = (struct bl_context *)ctx;

	return context->current_end_token;
}

DOTCONF_CB(toggle_option) {

	if (strcasecmp(cmd->name, "fallthroughaccept") == 0) {
		conf.default_accept = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "allownonport25") == 0) {
		conf.allow_non25 = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "dryrun") == 0) {
		conf.dryrun = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "allownonsyn") == 0) {
		conf.allow_nonsyn = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "quiet") == 0) {
		conf.quiet = cmd->data.value;
		return NULL;
	}	
	if (strcasecmp(cmd->name, "alternativedomain") == 0) {
		size_t sizechain = 0;
		conf.alt_domain = (char *)strdup(cmd->data.str);
		sizechain = strlen(conf.alt_domain);
		if (conf.alt_domain[sizechain-1] == '.') {
		conf.alt_domain[sizechain-1]='\0';
		}
		return NULL;
	}
	if (strcasecmp(cmd->name, "alternativeresolvefile") == 0) {
		size_t sizechain = 0;
		conf.alt_resolv_file = (char *)strdup(cmd->data.str);
		sizechain = strlen(conf.alt_resolv_file);
		if (conf.alt_resolv_file[sizechain-1] == '.') {
		conf.alt_resolv_file[sizechain-1]='\0';
		}
		return NULL;
	}
#ifdef USE_CACHE
	if (strcasecmp(cmd->name, "cachettl") == 0) {
		if (cmd->data.value < 0) {
			fprintf(stderr, "Error parsing config: cachettl cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		packet_cache_ttl = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "cachesize") == 0) {
		if (cmd->data.value < 0) {
			fprintf(stderr, "Error parsing config: cachelen cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		packet_cache_len = cmd->data.value;
		return NULL;
	}
#endif

	return NULL;
}

DOTCONF_CB(facility_option) {

	if (strcasecmp(cmd->data.str, "auth") == 0) {
		conf.log_facility = LOG_AUTH;
	} else if (strcasecmp(cmd->data.str, "authpriv") == 0) {
		conf.log_facility = LOG_AUTHPRIV;
	} else if (strcasecmp(cmd->data.str, "cron") == 0) {
		conf.log_facility = LOG_CRON;
	} else if (strcasecmp(cmd->data.str, "daemon") == 0) {
		conf.log_facility = LOG_DAEMON;
	} else if (strcasecmp(cmd->data.str, "kern") == 0) {
		conf.log_facility = LOG_KERN;
	} else if (strcasecmp(cmd->data.str, "lpr") == 0) {
		conf.log_facility = LOG_LPR;
	} else if (strcasecmp(cmd->data.str, "mail") == 0) {
		conf.log_facility = LOG_MAIL;
	} else if (strcasecmp(cmd->data.str, "news") == 0) {
		conf.log_facility = LOG_NEWS;
	} else if (strcasecmp(cmd->data.str, "syslog") == 0) {
		conf.log_facility = LOG_SYSLOG;
	} else if (strcasecmp(cmd->data.str, "user") == 0) {
		conf.log_facility = LOG_USER;
	} else if (strcasecmp(cmd->data.str, "uucp") == 0) {
		conf.log_facility = LOG_UUCP;
	} else if (strcasecmp(cmd->data.str, "local0") == 0) {
		conf.log_facility = LOG_LOCAL0;
	} else if (strcasecmp(cmd->data.str, "local1") == 0) {
		conf.log_facility = LOG_LOCAL1;
	} else if (strcasecmp(cmd->data.str, "local2") == 0) {
		conf.log_facility = LOG_LOCAL2;
	} else if (strcasecmp(cmd->data.str, "local3") == 0) {
		conf.log_facility = LOG_LOCAL3;
	} else if (strcasecmp(cmd->data.str, "local4") == 0) {
		conf.log_facility = LOG_LOCAL4;
	} else if (strcasecmp(cmd->data.str, "local5") == 0) {
		conf.log_facility = LOG_LOCAL5;
	} else if (strcasecmp(cmd->data.str, "local6") == 0) {
		conf.log_facility = LOG_LOCAL6;
	} else if (strcasecmp(cmd->data.str, "local7") == 0) {
		conf.log_facility = LOG_LOCAL7;
	} else {
		fprintf(stderr, "Log facility %s is invalid\n",
			cmd->data.str);
		exit(EXIT_FAILURE);
	}
	
	return NULL;
}

DOTCONF_CB(common_option) {

	struct config_entry *ce, *tmp=NULL;
#ifdef HAVE_FIREDNS
	size_t blacklistlen = 0;
#endif

	if (strcasecmp(cmd->name, "queueno") == 0) {
		conf.queueno = cmd->data.value;
		return NULL;
	}

	ce =  malloc(sizeof(struct config_entry));
	if (ce == NULL) {
		return NULL;
	}

	ce->string = (char *)strdup(cmd->data.str);
	ce->next = NULL;

	if (strcasecmp(cmd->name, "blacklistbl") == 0) {

#ifdef HAVE_FIREDNS
		blacklistlen = strlen(ce->string);
		if (ce->string[blacklistlen-1] == '.') {
			ce->string[blacklistlen-1]='\0';
		}
#endif

		/* resolution check completely removed.  Will put it back
		 * during config file and architectural revamp. */
		if (blacklistbl == NULL) {
			blacklistbl = ce;
			return NULL;
		} else {
			tmp = blacklistbl;
		}
	}

	if (strcasecmp(cmd->name, "whitelistbl") == 0) {

#ifdef HAVE_FIREDNS
		blacklistlen = strlen(ce->string);
		if (ce->string[blacklistlen-1] == '.') {
			ce->string[blacklistlen-1]='\0';
		}
#endif

		/* resolution check completely removed.  Will put it back
		 * during config file and architectural revamp. */
		if (whitelistbl == NULL) {
			whitelistbl = ce;
			return NULL;
		} else {
			tmp = whitelistbl;
		}
	}

	if (strcasecmp(cmd->name, "whitelist") == 0) {
		if (parse_cidr(ce) == -1) {
			fprintf(stderr, "Error parsing CIDR in %s, ignoring\n",
				ce->string);
			free(ce->string);
			free(ce);
			return NULL;
		}
		if (whitelist == NULL) {
			whitelist = ce;
			return NULL;
		} else {
			tmp = whitelist;
		}
	}

	if (strcasecmp(cmd->name, "blacklist") == 0) {
		if (parse_cidr(ce) == -1) {
			fprintf(stderr, "Error parsing CIDR in %s, ignoring\n",
				ce->string);
			free(ce->string);
			free(ce);
			return NULL;
		}
		if (blacklist == NULL) {
			blacklist = ce;
			return NULL;
		} else {
			tmp = blacklist;
		}
	}

	while (tmp->next != NULL) {
		tmp = tmp->next;
	}

	tmp->next = ce;

	return NULL;

}

DOTCONF_CB(host_section_open) {
	
	struct bl_context *context = (struct bl_context *)ctx;
	const char *old_end_token = context->current_end_token;
	int old_override = context->permissions;
	const char *err = NULL;

	context->permissions |= O_HOSTSECTION;
	context->current_end_token = end_host;

	while (!cmd->configfile->eof) {
		err = dotconf_command_loop_until_error(cmd->configfile);
		if (!err) {
			err = "</host> is missing";
			break;
		}
	
		if (err == context->current_end_token)
			break;
	
		dotconf_warning(cmd->configfile, DCLOG_ERR, 0, err);
	}

	context->current_end_token = old_end_token;
	context->permissions = old_override;

	if (err != end_host)
		return err;

	return NULL;

}

/*
 * SYNOPSIS:
 *   int parse_cidr(
 *                  struct config_entry *ce
 *                 );
 *
 * ARGUMENTS:
 *   struct config_entry *ce      Structure to be filled in, ->string must
 *                                be supplied.
 *
 * RETURN VALUE:
 *   On success 0 is returned, non-zero is returned on error.
 *
 * NOTES:
 *   This routine is rather tortured, but it works and is believed
 *   correct.  Please don't mess with it without a good reason.
 *
 */
int parse_cidr(struct config_entry *ce) {

	int sep = 0;			// which separator we're on.
	char *counter, *c1;
	char number[BUFFERSIZE];

	if (ce == NULL) {
		return -1;
	}

	c1 = ce->string; // initialize state counter

	for (counter = ce->string; 
			(counter - ce->string) < strlen(ce->string); 
			counter++) {
		switch (*counter) {
			case '.':
			case '/':
				// separator
				strncpy(number, c1, (int)(counter - c1));
				number[(int)(counter - c1)] = '\0';
				switch(sep) {
					case 0:
						ce->ip.b1 = atoi(number);
						if (ce->ip.b1 < 0 ||
							ce->ip.b1 > 255) {
							return -1;
						}
						break;
					case 1:
						ce->ip.b2 = atoi(number);
						if (ce->ip.b2 < 0 ||
							ce->ip.b2 > 255) {
							return -1;
						}
						break;
					case 2:
						ce->ip.b3 = atoi(number);
						if (ce->ip.b3 < 0 ||
							ce->ip.b3 > 255) {
							return -1;
						}
						break;
					case 3:
						ce->ip.b4 = atoi(number);
						if (ce->ip.b4 < 0 ||
							ce->ip.b4 > 255) {
							return -1;
						}
						break;
				}
				sep++;
				c1 = counter + 1;
				break;
			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				continue;
			default:
				// this character doesn't belong here.
				return -1;
				break;
		}
	}		
	strncpy (number, c1, (int)(counter - c1));
	number[(int)(counter - c1)] = '\0';
	ce->cidr.network = atoi(number);

	ce->cidr.processed = 0;
	ce->cidr.processed = 0xffffffff << (32 - ce->cidr.network);

	ce->cidr.ip = 0;
	ce->cidr.ip = ce->ip.b1 << 24;
	ce->cidr.ip |= ce->ip.b2 << 16;
	ce->cidr.ip |= ce->ip.b3 << 8;
	ce->cidr.ip |= ce->ip.b4;

	/* Mask out the bits that aren't in the network in cidr.ip.
	 * We don't care about them and they'll just confuse the issue. */
	ce->cidr.ip &= ce->cidr.processed;

	return 0;

}

/*
 * this routine isn't necessary right now.
int validate_blacklist(char *str) {

	struct hostent *host;

	assert(str != NULL);

	host = gethostbyname(str);

	if (host == NULL && h_errno != NETDB_SUCCESS) {
		return -1;
	}
	
	return 0;
}
*/


/*
 * SYNOPSIS:
 *   int check_packet_dnsbl(
 *                          const struct packet_info 
 *                          struct config_entry *list
 *                         );
 *
 * ARGUMENTS:
 *   struct packet_info *ip       IP address data to check in DNS RBL.
 *   struct config_entry *list    Configured DNS RBL to check.
 *
 * RETURN VALUE:
 *   0 is returned if the "ip" cannot be found in the given "list".  1 is
 *   returned on a successful match.
 *
 * NOTES:
 *   "check_packet_dnsbl"  searches the given list parameter (which is a list
 *   of configured DNS RBLs in ->string) to determine if the data passed in
 *   "ip" should be blocked.
 *   This function must be able to cope with NULL "ip" and "list" paramters
 *   without aborting.
 *
 */
int check_packet_dnsbl(const struct packet_info *ip, struct config_entry *list) {

	struct config_entry *wltmp = NULL;
	char dns_ip[20];
#ifndef HAVE_FIREDNS
	struct hostent *host;
#else
	struct in_addr *host;
#endif

	if (ip == NULL || list == NULL) {
		return 0;
	}

	//~ ldns_resolver *resAux = res;
	wltmp = list;
	
	while (1) {

		char lookupbuf[BUFFERSIZE];
	
		snprintf(lookupbuf, sizeof(lookupbuf), "%hhu.%hhu.%hhu.%hhu.%s", ip->b4, ip->b3, ip->b2, ip->b1,
			wltmp->string);
		
		// syslog(LOG_ERR, "Checking server %s", wltmp->string );    // print in log the current domain

		// If domain contains zevenet domain, send it directly to zevenet nameserver
		if(regexec(&regex, wltmp->string, (size_t) 0, NULL, 0) != REG_NOMATCH )
		{
			DEBUG(1, "Sending to optional DNS");
			if ( direct_dns_resolv ( res, lookupbuf ) )
			{
				// found
				return 1;
			}
		}
		else
		{
			DEBUG(1, "Sending to default DNS");
#ifndef HAVE_FIREDNS
			host = gethostbyname(lookupbuf);
#else
			host = firedns_resolveip4(lookupbuf);
#endif
		
			if (host == NULL) {
#ifndef HAVE_FIREDNS
				if (h_errno != HOST_NOT_FOUND) {
					syslog(LOG_ERR, "Error looking up host %s",
						lookupbuf	
					);
				}
#else
			;
#endif
			} else {
				// found.
				return 1;
			}
		}
		
		if (wltmp->next == NULL) {
			/* Termination case */
			return 0;
		}

		wltmp = wltmp->next;
	}

	return 0;
}

/*
 * SYNOPSIS:
 *   int check_packet_list(
 *                          const struct packet_info *ip
 *                          struct config_entry *list
 *                         );
 *
 * ARGUMENTS:
 *   struct packet_info *ip       IP address data to check in supplied list. 
 *   struct config_entry *list    List that contains data to check in against,
 *                                whitelist for example.
 *
 * RETURN VALUE:
 *   0 is returned if the "ip" cannot be found in the given "list".  1 is
 *   returned on a successful match.
 *
 * NOTES:
 *   "check_packet_list"  searches the given list parameter (which is a list
 *   CIDRs) to determine if the data passed in "ip" matches (whitelist, for
 *   for example).
 *   This function must be able to cope with NULL "ip" and "list" paramters
 *   without aborting.
 *
 */
int check_packet_list(const struct packet_info *ip, struct config_entry *list) {

	struct config_entry *wltmp = NULL;
	unsigned int ip_proc;

	if (ip == NULL || list == NULL) {
		return 0;
	}

	ip_proc = ip->b1 << 24;
	ip_proc |= ip->b2 << 16;
	ip_proc |= ip->b3 << 8;
	ip_proc |= ip->b4;

	wltmp = list;

	while (1) {
		uint32_t p = 0;

		p = ip_proc;
		p &= wltmp->cidr.processed;

		if (p == wltmp->cidr.ip) {
			snprintf(msgbuf, sizeof(msgbuf), "%hhu.%hhu.%hhu.%hhu %x/%d",
				ip->b1, ip->b2, ip->b3, ip->b4,
				wltmp->cidr.ip, wltmp->cidr.network);
			return 1;
		}

		if (wltmp->next == NULL) {
			break;
		}

		wltmp = wltmp->next;
	}
	return 0;
}

/*
 * SYNOPSIS:
 *   static void get_ip_string(
 *                             const struct packet_info *ip
 *                            );
 *
 * ARGUMENTS:
 *   struct packet_info *ip       Structure containing IP parts to construct
 *                                the ASCII representation from.
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 *   This function takes the data in the parameter "ip" and stores an ASCII
 *   representation in the global variable "msgbuf."
 *   It must be able to cope with "ip" being NULL.
 *
 */
static void get_ip_string(const struct packet_info *ip) {

	if (ip == NULL) {
		sprintf(msgbuf, "-");
		return;
	}

	snprintf(msgbuf, sizeof(msgbuf), "%hhu.%hhu.%hhu.%hhu:%d.%d", ip->b1, 
		ip->b2, ip->b3, ip->b4,
		ip->s_port,ip->d_port);
	return;
}

#ifdef USE_SOCKSTAT
/*
 * SYNOPSIS:
 *   void *pbl_sockstat_thread(
 *                             void *tdata
 *                            );
 *
 * ARGUMENTS:
 *   void *tdata                  Data to pass into the thread.  This is unused
 *                                currently.
 *
 * RETURN VALUE:
 *   This function always returns NULL.
 *
 * NOTES:
 */
void *pbl_sockstat_thread(void *tdata) {
	struct sockaddr_un sockinfo;
	FILE *sockfp = NULL;
	char buf[1024]={0};
	time_t current_time;
	int master_sockfd, sockfd;
	int bindret, listenret, snprintfret;
	int sockinfolen;

	/* Delete any stray sockets left lying around. */
	unlink(SOCKSTAT_PATH);

	/* Create a UNIX domain socket. */
	master_sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (master_sockfd < 0) {
		syslog(LOG_ERR, "Error creating socket: %s",
			strerror(errno));
		pthread_exit(NULL);
	}

	/* Bind our socket to the pathname. */
	sockinfo.sun_family = AF_UNIX;
	strncpy(sockinfo.sun_path, SOCKSTAT_PATH, sizeof(sockinfo.sun_path));
	bindret = bind(master_sockfd, 
		(struct sockaddr *) &sockinfo, sizeof(sockinfo));
	if (bindret < 0) {
		syslog(LOG_ERR, "Error binding to socket: %s",
			strerror(errno));
		if (close(master_sockfd) < 0) {
			syslog(LOG_ERR, "%s:%d close() failed: %s",
				__FILE__,__LINE__, strerror(errno));
		}
		pthread_exit(NULL);
	}

	/* Start listening for connections. */
	listenret = listen(master_sockfd, 3);
	if (listenret < 0) {
		syslog(LOG_ERR, "Error listening on socket: %s",
			strerror(errno));
		if (close(master_sockfd) < 0) {
			syslog(LOG_ERR, "%s:%d close() failed: %s",
				__FILE__,__LINE__, strerror(errno));
		}
		if (unlink(SOCKSTAT_PATH) < 0) {
			syslog(LOG_ERR, "%s:%d removing socket failed: %s",
				__FILE__,__LINE__, strerror(errno));
		}
		pthread_exit(NULL);
	}

	current_time = time(NULL);
	ctime_r(&current_time, buf);

	while (1) {
		sockinfolen = sizeof(sockinfo);

		sockfd = accept(master_sockfd, 
			(struct sockaddr *) &sockinfo, &sockinfolen);

		if (sockfd < 0) continue;

		sockfp = fdopen(sockfd, "w");
		if (sockfp == NULL) {
			if (close(sockfd) < 0) {
				syslog(LOG_ERR, "%s:%d close() failed: %s",
					__FILE__,__LINE__, strerror(errno));
			}
			continue;
		}

		fprintf(sockfp, "Running since: %s", buf);
		fprintf(sockfp, "Statistics:\n");
		fprintf(sockfp, "  Cache hits (accept): %d\n", 
			statistics.cacheaccept);
		fprintf(sockfp, "  Cache hits (reject): %d\n", 
			statistics.cachereject);
		fprintf(sockfp, "  DNS Whitelist hits: %d\n", 
			statistics.whitelistblhits);
		fprintf(sockfp, "  DNS Blacklist hits: %d\n", 
			statistics.blacklistblhits);
		fprintf(sockfp, "  Whitelist hits: %d\n", 
			statistics.whitelisthits);
		fprintf(sockfp, "  Blacklist hits: %d\n", 
			statistics.blacklisthits);
		fprintf(sockfp, "  Fall through hits: %d\n", 
			statistics.fallthroughhits);
		fprintf(sockfp, "  Total packets: %d\n", 
			statistics.totalpackets);
		fclose(sockfp);
	}

	close(master_sockfd);
	if (close(master_sockfd) < 0) {
		syslog(LOG_ERR, "%s:%d close() failed: %s",
			__FILE__,__LINE__, strerror(errno));
	}

	/* Cleanup sockets. */
	if (unlink(SOCKSTAT_PATH) < 0) {
		syslog(LOG_ERR, "%s:%d removing socket failed: %s",
			__FILE__,__LINE__, strerror(errno));
	}

	/* Terminate our thread without taking down the entire process. */
	pthread_exit(NULL);

	/* This should never be reached. */
	return(NULL);
}

/*
 * SYNOPSIS:
 *   void pbl_init_sockstat(void);
 *
 * ARGUMENTS:
 *   (none)
 *
 * RETURN VALUE:
 *   (none)
 *
 * NOTES:
 */
void pbl_init_sockstat(void) {
	pthread_t pthread_data;
	int pthread_ret = 0;

	/* Create the thread to handle socket requests. */
	pthread_ret = pthread_create(
		&pthread_data, NULL, pbl_sockstat_thread, NULL);
	if (pthread_ret < 0) {
		syslog(LOG_ERR, "pthread_create failed: %s",
			strerror(errno));
	}

	return;
}

#endif

