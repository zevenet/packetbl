
/* Copyright 2004 Russell Miller
	Copyright 2017 Alvaro Cano <alvaro.cano@zevenet.com>
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

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
#include <regex.h>
#include <pthread.h>
#include <unistd.h>
#include <stdarg.h>

#include "packetbl.h"
#include "directresolv.h"

#ifdef HAVE_FIREDNS
#include <firedns.h>
#endif

#ifndef BUFFERSIZE
#define BUFFERSIZE 65536
#endif
#ifdef USE_CACHE
#ifndef USE_CACHE_DEF_LEN
#define USE_CACHE_DEF_LEN 8192
#endif
#ifndef USE_CACHE_DEF_TTL
#define USE_CACHE_DEF_TTL 3600
#endif
#endif

#define TH_FIN        0x01
#define TH_SYN        0x02
#define TH_RST        0x04
#define TH_PUSH       0x08
#define TH_ACK        0x10
#define TH_URG        0x20

#include <libnetfilter_queue/libnetfilter_queue.h>
#define SET_VERDICT nfq_set_verdict
#define PBL_HANDLE nfq_q_handle
#define PBL_SET_MODE nfq_set_mode
#define PBL_COPY_PACKET NFQNL_COPY_PACKET
#define PBL_ID_T u_int32_t
#define PBL_ERRSTR ""

#define MAXBUF      4096

#define DEBUG(x, y) if (conf.debug >= x) { printf(y "\n"); }
#define LOGGING(x, de, string) if (conf.debug >= x) { printf(y "\n"); }
struct packet_info
{

	// Source info
	uint8_t s_ip_b1;
	uint8_t s_ip_b2;
	uint8_t s_ip_b3;
	uint8_t s_ip_b4;
	int s_port;

	// Destination info
	uint8_t d_ip_b1;
	uint8_t d_ip_b2;
	uint8_t d_ip_b3;
	uint8_t d_ip_b4;
	int d_port;

	int flags;
};

struct cidr
{

	uint32_t ip;
	uint32_t network;
	uint32_t processed;	/* network, but as a bitmask */

};

struct config_entry
{

	char *string;
	struct config_entry *next;
	struct packet_info ip;
	struct cidr cidr;

};


// parameters to create a thread
struct thr_arg
{
	struct nfq_q_handle *queue_handle;	// nf_queue id
	struct packet_info ip;
	int id;
};


struct thr_parameters
{
	pthread_attr_t *thr_attr;	// argument
	pthread_t *thr;		// parameters
};


struct config_entry *blacklistbl = NULL;
struct config_entry *whitelistbl = NULL;
struct config_entry *blacklist = NULL;
struct config_entry *whitelist = NULL;

// Execution parameters
// Only check configuration file
int arg_debug = 0;
int arg_quiet = 0;
char *packetbl_configfile = NULL;
char *packetbl_pidfile = NULL;

// to query to a alternative nameserver

struct bl_context
{

	int permissions;
	const char *current_end_token;

};

static pthread_mutex_t lock_queue;
static pthread_mutex_t lock_cache;
static pthread_mutex_t lock_count;

// thread counter
volatile int thread_count;

static double
cur_time(void)
{
	return time(NULL) * 1000000.0;
}


enum permissions
{
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
char rulemsgbuf[MAXBUF];
char ipmsgbuf[MAXBUF];

struct config
{
	char *name;
	int allow_non25;
	int allow_nonsyn;
	int default_accept;
	int dryrun;
	int log_facility;
	int log_level;
	int queueno;
	int quiet;
	int quiet_wl;
	int quiet_bl;
	char *alt_resolv_file;
	char *alt_domain;
	int debug;
	int queue_size;
	int threads_max;
};
static struct config conf = {
	NULL,
	0,
	0,
	1,
	0,
	LOG_DAEMON,
	5,
	0,
	0,
	0,
	0,
	NULL,
	NULL,
	0,
	0,
	0
};


// struct to save regexp of domain
static regex_t regex;

struct pbl_stat_info
{
	uint32_t cacheaccept;
	uint32_t cachereject;
	uint32_t whitelistblhits;
	uint32_t blacklistblhits;
	uint32_t whitelisthits;
	uint32_t blacklisthits;
	uint32_t fallthroughhits;
	uint32_t totalpackets;
};
static struct pbl_stat_info statistics = { 0, 0, 0, 0, 0, 0, 0, 0 };

#ifdef USE_CACHE
struct packet_cache_t
{
	uint32_t ipaddr;
	time_t expires;
	int action;
};
volatile struct packet_cache_t *packet_cache = NULL;
uint32_t packet_cache_len = USE_CACHE_DEF_LEN;
uint16_t packet_cache_ttl = USE_CACHE_DEF_TTL;
#endif

struct config_entry *hostlistcache = NULL;


void logmsg(const int priority, const int debug, const char *fmt, ...);
#if NETFILTERQUEUE_VERSION_NUMBER == 0
int get_packet_info(char *payload, struct packet_info *ip);
#else
int get_packet_info(unsigned char *payload, struct packet_info *ip);
#endif
int check_packet_list(const struct packet_info *ip,
		      struct config_entry *list);
int check_packet_dnsbl(const struct packet_info *ip,
		       struct config_entry *list);
int parse_cidr(struct config_entry *ce);
/* int validate_blacklist(char *); */
void parse_config(void);
void print_help(void);
void parse_arguments(int argc, char **argv);
void pbl_init_sockstat(void);
static void get_ip_string(const struct packet_info *ip);
static void pbl_set_verdict(struct PBL_HANDLE *h, PBL_ID_T id,
			    unsigned int verdict);

static int callback_threads(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
			    struct nfq_data *nfa, void *thread_hd);
void pbl_callback(void *data);


static const configoption_t options[] = {
	{"name", ARG_STR, common_option, NULL, O_ROOT},
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
	{"quietwl", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"quietbl", ARG_TOGGLE, toggle_option, NULL, O_ROOT},
	{"alternativedomain", ARG_STR, toggle_option, NULL, O_ROOT},
	{"alternativeresolvefile", ARG_STR, toggle_option, NULL, O_ROOT},
#ifdef USE_CACHE
	{"cachettl", ARG_INT, toggle_option, NULL, O_ROOT},
	{"cachesize", ARG_INT, toggle_option, NULL, O_ROOT},
#endif
	{"logfacility", ARG_STR, facility_option, NULL, O_ROOT},
	{"loglevel", ARG_INT, toggle_option, NULL, O_ROOT},
	{"queueno", ARG_INT, toggle_option, NULL, O_ROOT},
	{"queuesize", ARG_INT, toggle_option, NULL, O_ROOT},
	{"threadmax", ARG_INT, toggle_option, NULL, O_ROOT},
	LAST_OPTION
};

FUNC_ERRORHANDLER(error_handler)
{

	fprintf(stderr, "[error] %s\n", msg);
	return 1;

}




/*
 * Log an error to the syslog or to stderr
 */
void
logmsg(const int debug, const int priority, const char *fmt, ...)
{
	char buf[MAXBUF + 1];
	va_list ap;

	buf[MAXBUF] = '\0';
	va_start(ap, fmt);
	vsnprintf(buf, MAXBUF, fmt, ap);
	va_end(ap);
	if (debug >= 0) {
		if (conf.debug > debug)
			printf("%s\n", buf);
	}

	if (conf.log_level >= priority)
		syslog(priority, "%s", buf);

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
void
daemonize(void)
{

	pid_t pid;
	FILE *pidf;

	chdir("/");

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	setsid();

	pid = fork();

	if (pid > 0) {
		if (packetbl_pidfile != NULL) {
			pidf = fopen(packetbl_pidfile, "w");
			if (!pidf) {
				logmsg(0, LOG_ERR, "Can't write PID %d to %s",
				       (int) pid, packetbl_pidfile);
			}
			else {
				fprintf(pidf, "%d\n", (int) pid);
				fclose(pidf);
			}
			exit(EXIT_SUCCESS);
		}
	}
	if (pid < 0) {
		logmsg(0, LOG_ERR, "Fork failed while daemonizing: %s",
		       strerror(errno));
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
static uint32_t
packet_cache_hash(const struct packet_info ip)
{
	uint32_t hash = 0;

	hash = ip.s_ip_b1 << 6;
	hash += ip.s_ip_b2 << 4;
	hash += ip.s_ip_b3 << 2;
	hash += ip.s_ip_b4;
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
void
packet_cache_clear(void)
{
	uint32_t i;

	if (packet_cache == NULL)
		return;

	for (i = 0; i < packet_cache_len; i++) {
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
static uint32_t
packet_info_to_ip(const struct packet_info ip)
{
	return ((ip.s_ip_b1 & 0xff) << 24) |
		((ip.s_ip_b2 & 0xff) << 16) |
		((ip.s_ip_b3 & 0xff) << 8) | (ip.s_ip_b4 & 0xff);
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
int
packet_check_ip(const struct packet_info ip)
{

	int retval = NF_ACCEPT;
	struct pbl_stat_info *statics_pointer = &statistics;
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

	if (cache_hash > 0 && cache_hash < packet_cache_len
	    && packet_cache != NULL) {
		if (packet_cache[cache_hash].ipaddr == ipaddr_check
		    && packet_cache[cache_hash].expires > currtime) {
			get_ip_string(&ip);
			retval = packet_cache[cache_hash].action;
			switch (retval) {
			case NF_DROP:
				actionstr = "reject";
				statics_pointer->cachereject++;
				if (!conf.quiet_bl)
					logmsg(0, LOG_INFO,
					       "%s [Found in cache (%s)] [%s]",
					       conf.name, actionstr,
					       ipmsgbuf);
				break;
			case NF_ACCEPT:
				actionstr = "accept";
				statics_pointer->cacheaccept++;
				if (!conf.quiet_wl)
					logmsg(0, LOG_INFO,
					       "%s [Found in cache (%s)] [%s]",
					       conf.name, actionstr,
					       ipmsgbuf);
				break;
			default:
				actionstr = "???";
				break;
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
		if (!conf.quiet_wl)
			logmsg(0, LOG_NOTICE,
			       "%s [accept whitelist (%s)] [%s]", conf.name,
			       rulemsgbuf, ipmsgbuf);
		statics_pointer->whitelisthits++;
		retval = NF_ACCEPT;

	}
	else if (check_packet_list(&ip, blacklist) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet_bl)
			logmsg(0, LOG_NOTICE,
			       "%s [reject blacklist (%s)] [%s]", conf.name,
			       rulemsgbuf, ipmsgbuf);
		statics_pointer->blacklisthits++;
		retval = NF_DROP;

	}
	else if (check_packet_dnsbl(&ip, whitelistbl) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet_wl)
			logmsg(0, LOG_NOTICE, "%s [accept dnsbl (%s)] [%s]",
			       conf.name, rulemsgbuf, ipmsgbuf);
		statics_pointer->whitelistblhits++;
		retval = NF_ACCEPT;

	}
	else if (check_packet_dnsbl(&ip, blacklistbl) == 1) {
		get_ip_string(&ip);
		if (!conf.quiet_bl)
			logmsg(0, LOG_NOTICE, "%s [reject dnsbl (%s)] [%s]",
			       conf.name, rulemsgbuf, ipmsgbuf);
		statics_pointer->blacklistblhits++;
		retval = NF_DROP;

	}
	else {
		get_ip_string(&ip);
		if (conf.default_accept == 1) {
			if (!conf.quiet_wl)
				logmsg(0, LOG_INFO,
				       "%s [accept fallthrough] [%s]",
				       conf.name, ipmsgbuf);
			retval = NF_ACCEPT;

		}
		else {
			if (!conf.quiet_bl)
				logmsg(0, LOG_INFO,
				       "%s [reject fallthrough] [%s]",
				       conf.name, ipmsgbuf);
			retval = NF_DROP;

		}
		statics_pointer->fallthroughhits++;
	}

#ifdef USE_CACHE
	pthread_mutex_lock(&lock_cache);
	/* Put current action into the cache. */
	if (packet_cache != NULL) {
		packet_cache[cache_hash].ipaddr = ipaddr_check;
		packet_cache[cache_hash].action = retval;
		packet_cache[cache_hash].expires =
			currtime + packet_cache_ttl;
	}
	pthread_mutex_unlock(&lock_cache);
#endif

	return retval;
}


void
pbl_callback(void *arguments)
{

	int ret = 0;
	struct nfqnl_msg_packet_hdr *ph = NULL;

	if (conf.debug > 3) {
		pthread_mutex_lock(&lock_count);
		thread_count++;
		logmsg(3, LOG_DEBUG, "Thread openned [%d]", thread_count);
		pthread_mutex_unlock(&lock_count);
	}

	// function parameters
	struct packet_info ip;
	struct nfq_q_handle *qh =
		((struct thr_arg *) arguments)->queue_handle;
	int id = ((struct thr_arg *) arguments)->id;

	memcpy(&ip, &((struct thr_arg *) arguments)->ip,
	       sizeof(struct packet_info));

	free(arguments);
	arguments = NULL;

	ret = packet_check_ip(ip);

	if (ret == NF_ACCEPT || ret == NF_DROP) {
		logmsg(2, LOG_DEBUG,
		       "Got packet from %hhu.%hhu.%hhu.%hhu: %d\n",
		       ip.s_ip_b1, ip.s_ip_b2, ip.s_ip_b3, ip.s_ip_b4, ret);
		pbl_set_verdict(qh, id, ret);
	}

	if (conf.debug > 3) {
		pthread_mutex_lock(&lock_count);
		thread_count--;
		logmsg(3, LOG_DEBUG, "Thread closed [%d]", thread_count);
		pthread_mutex_unlock(&lock_count);
	}

	return;
}




// Create a new thread for the current packet
static int
callback_threads(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
		 struct nfq_data *nfa, void *thread_attr)
{

	// Creating thread parameters
	struct thr_arg *argp = NULL;
	int id = 0;
	int ret = 0;
	struct nfqnl_msg_packet_hdr *ph = NULL;
#if NETFILTERQUEUE_VERSION_NUMBER == 0
	char *nfdata = NULL;
#else
	unsigned char *nfdata = NULL;
#endif
	struct packet_info ip;


	ph = nfq_get_msg_packet_hdr(nfa);
	if (ph != NULL) {
		id = ntohl(ph->packet_id);
	}

	ret = nfq_get_payload(nfa, &nfdata);
	/* what return codes here? */

	ret = get_packet_info(nfdata, &ip);
	pthread_mutex_unlock(&lock_queue);
	if (ret == -1) {
		pbl_set_verdict(qh, id, NF_ACCEPT);
		logmsg(0, LOG_ERR, "Error reading packet. Accepting packet.");
		return 1;
	}

	if (conf.threads_max) {
		pthread_mutex_lock(&lock_count);
		if (thread_count > conf.threads_max) {
			pthread_mutex_unlock(&lock_count);
			pbl_set_verdict(qh, id, NF_ACCEPT);
			logmsg(0, LOG_ERR,
			       "Thread queue full. Accepting packet.");
			return 1;
		}
		pthread_mutex_unlock(&lock_count);
	}

	if ((argp = malloc(sizeof(struct thr_arg))) == NULL) {
		pbl_set_verdict(qh, id, NF_ACCEPT);
		logmsg(0, LOG_ERR, "thr_arg malloc");
		return 1;
	}

	argp->queue_handle = qh;
	argp->id = id;
	memcpy(&argp->ip, &ip, sizeof(struct packet_info));

	if (pthread_create
	    (((struct thr_parameters *) thread_attr)->thr,
	     ((struct thr_parameters *) thread_attr)->thr_attr,
	     (void *) &pbl_callback, (void *) argp) != 0) {
		free(argp);
		pbl_set_verdict(qh, id, NF_ACCEPT);
		logmsg(0, LOG_ERR, "Error creating thread: %d.",
		       thread_count);
	}
	return 0;
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
static void
pbl_set_verdict(struct PBL_HANDLE *h, PBL_ID_T id, unsigned int verdict)
{
	pthread_mutex_lock(&lock_queue);
	if (conf.dryrun == 1) {
		SET_VERDICT(h, id, NF_ACCEPT, 0, NULL);
	}
	else {
		SET_VERDICT(h, id, verdict, 0, NULL);
	}
	pthread_mutex_unlock(&lock_queue);
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
int
main(int argc, char **argv)
{

	struct PBL_HANDLE *handle = NULL;
	char buf[BUFFERSIZE];
	struct nfq_handle *h;
	struct nfnl_handle *nh;
	int fd;
	struct stat fbuf;
	int rv;
	char work_directory[MAXBUF];

	pthread_attr_t thr_attr;
	pthread_t thr;

#ifdef USE_NF_FAILOPEN
	uint32_t flags = NFQA_CFG_F_FAIL_OPEN;
	uint32_t mask = NFQA_CFG_F_FAIL_OPEN;
#endif

	struct thr_parameters new_thr_arg;
	new_thr_arg.thr = &thr;
	new_thr_arg.thr_attr = &thr_attr;
	thread_count = 0;

	pthread_mutex_init(&lock_count, NULL);

	// debug level
	conf.debug = 0;
	conf.threads_max = 0;

	if (stat("/proc/net/netfilter/nfnetlink_queue", &fbuf) == ENOENT) {
		fprintf(stderr,
			"Please make sure you have\ncompiled a kernel with the Netfilter QUEUE target built in, or loaded the appropriate module.\n");
		exit(EXIT_FAILURE);
	}

	/* Parse execution arguments. */
	parse_arguments(argc, argv);

	/* Parse our configuration data. */
	parse_config();

	openlog("packetbl", LOG_PID, conf.log_facility);

	if (arg_debug)
		conf.debug = arg_debug;

	if (arg_quiet == 1)
		conf.quiet = 1;

	logmsg(0, LOG_DEBUG, "Debug level %d", conf.debug);
	logmsg(0, LOG_DEBUG, "Linking to queue %d", conf.queueno);

	if (conf.debug == 0)
		daemonize();

#ifdef USE_CACHE
	if (packet_cache_len > 0) {
		/* Allocate space for the packet cache if a positive number of
		   elements is requested. */
		packet_cache =
			malloc(sizeof(*packet_cache) * packet_cache_len);
	}
	else {
		packet_cache = NULL;
	}

	packet_cache_clear();
#endif

	// Creating alternative nameservers to do request directly to ZEVENET domain
	if (conf.alt_domain && conf.alt_resolv_file) {
		getcwd(work_directory, sizeof(work_directory));
		logmsg(0, LOG_DEBUG, "Loading nameserver file from: %s%s.",
		       work_directory, conf.alt_resolv_file);

		// creating regexp to compare request domain with a specific domain
		if (regcomp(&regex, conf.alt_domain, 0) != 0) {
			logmsg(0, LOG_ERR, "Create regexp failed");
			exit(EXIT_FAILURE);
		}

	}

	/* thread stuff */
	pthread_attr_init(&thr_attr);
	pthread_attr_setdetachstate(&thr_attr, PTHREAD_CREATE_DETACHED);

	// initializing nfqueue
	logmsg(2, LOG_DEBUG, "Creating nfq handle...");
	if ((h = nfq_open()) == NULL) {
		logmsg(1, LOG_ERR, "Couldn't create nfq handle: %s",
		       strerror(errno));
		exit(EXIT_FAILURE);
	}
	logmsg(2, LOG_DEBUG, "unbinding nfq handle...");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		logmsg(1, LOG_ERR,
		       "Couldn't unbind nf_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	logmsg(2, LOG_DEBUG, "binding nfq handle...");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		logmsg(1, LOG_ERR,
		       "Couldn't bind ns_queue handler for AF_INET");
		exit(EXIT_FAILURE);
	}
	logmsg(2, LOG_DEBUG, "creating queue...");
	if ((handle =
	     nfq_create_queue(h, conf.queueno, &callback_threads,
			      (void *) &new_thr_arg)) == NULL) {
		logmsg(1, LOG_ERR, "nfq_create_queue failed");
		exit(EXIT_FAILURE);
	}

#ifdef USE_NF_FAILOPEN
	logmsg(2, LOG_DEBUG, "Configuring fail-open flag...");
	// Accept packet if queue is full
	if (nfq_set_queue_flags(handle, mask, flags) == -1) {
		logmsg(1, LOG_ERR, "nfq_set_queue_flags failed");
		exit(EXIT_FAILURE);
	}
#endif


	if ((PBL_SET_MODE(handle, PBL_COPY_PACKET, BUFFERSIZE)) == -1) {
		logmsg(1, LOG_ERR, "ipq_set_mode error: %s", PBL_ERRSTR);
		if (errno == 111) {
			logmsg(0, LOG_ERR, "try loading the ip_queue module");
		}
		exit(EXIT_FAILURE);
	}

	// configure a queue size
	if (conf.queue_size) {
		if (nfq_set_queue_maxlen(handle, conf.queue_size)) {
			logmsg(1, LOG_ERR, "nfq_set_queue_maxlen");
			exit(EXIT_FAILURE);
		}
	}

	logmsg(1, LOG_INFO, "packetbl started successfully");

	/* main packet processing loop.  This loop should never terminate
	 * unless a signal is received or some other unforeseen thing
	 * happens.
	 */
	while (1) {

		nh = nfq_nfnlh(h);
		fd = nfnl_fd(nh);
		logmsg(2, LOG_DEBUG, "Entering main loop.");

		while ((rv = recv(fd, buf, sizeof(buf), 0)) > 0) {
			if (rv > 0) {
				pthread_mutex_lock(&lock_queue);
				logmsg(2, LOG_DEBUG, "Handling a packet");
				nfq_handle_packet(h, buf, rv);
			}
		}
		logmsg(2, LOG_DEBUG, "Packet got.");
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
#if NETFILTERQUEUE_VERSION_NUMBER == 0
int
get_packet_info(char *payload, struct packet_info *ip)
{
#else
int
get_packet_info(unsigned char *payload, struct packet_info *ip)
{
#endif

	int version;
	int ip_header_length, header_size;

	if (ip == NULL || payload == NULL) {
		return -1;
	}

	ip->s_port = 0;
	ip->d_port = 0;

	/* Get IP Version               Byte 1 of IP Header */
	version = payload[0] & 0xF0;
	version >>= 4;
	/* Get IP Header length         Byte 2 of IP Header
	 * Header length is usually 20, or 5 32-bit words */
	ip_header_length = payload[0] & 0x0F;
	header_size = ip_header_length * 4;

	/* We're not handling IPV6 packets yet.  I'll probably rewrite
	 * this whole damned thing in C++ first. */
	if (version != 4) {
		return -1;
	}

	/* source IP Address                        Bytes 13 - 16 of IP header */
	ip->s_ip_b1 = payload[12];
	ip->s_ip_b2 = payload[13];
	ip->s_ip_b3 = payload[14];
	ip->s_ip_b4 = payload[15];

	/* destination IP Address                   Bytes 17 - 20 of IP header */
	ip->d_ip_b1 = payload[16];
	ip->d_ip_b2 = payload[17];
	ip->d_ip_b3 = payload[18];
	ip->d_ip_b4 = payload[19];

	/* Source Port                  Bytes 21 - 22 of IP Header
	 *                              Bytes 1 - 2 of TCP Header */
	ip->s_port = payload[header_size] * 256;
	ip->s_port += payload[header_size + 1];

	/* Destination Port             Bytes 23 - 24 of IP Header
	 *                              Bytes 3 - 4 of TCP Header */
	ip->d_port = payload[header_size + 2] * 256;
	ip->d_port += payload[header_size + 3];

	/* TCP Flags                    Byte 14 of TCP header
	 *                              Last six bits
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
 * void parse_config( void );
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
void
parse_config(void)
{

	configfile_t *configfilehandle;
	struct bl_context context;

	if (packetbl_configfile == NULL) {
		configfilehandle =
			dotconf_create(CONFIGFILE, options, (void *) &context,
				       CASE_INSENSITIVE);
	}
	else {
		configfilehandle =
			dotconf_create(packetbl_configfile, options,
				       (void *) &context, CASE_INSENSITIVE);
	}

	if (!configfilehandle) {
		fprintf(stderr, "Error opening config file\n");
		exit(EXIT_FAILURE);
	}

	if (dotconf_command_loop(configfilehandle) == 0) {
		fprintf(stderr, "Error reading configuration file\n");
		exit(EXIT_FAILURE);
	}

	dotconf_cleanup(configfilehandle);

	return;
}



void
print_help(void)
{
	printf("Usage: packetbl [OPTION]...\n\
	-h\t\t- Show this help	\n\
	-f <FILE>\t- Choose a config file\n\
	-q\t\t- Run the binary in quiet mode, packetbl does not log the veredict\n\
	-p <FILE>\t- Set a PID file \n\
	-V\t\t- Show packetbl version	\n\
	-d <level>\t- Run packetbl with a debug level \n");
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
void
parse_arguments(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "hf:qp:Vd:")) != -1) {
		switch (ch) {
			// print packetbl help
		case 'h':
			print_help();
			exit(EXIT_SUCCESS);
			break;
			// no loggin packetbl veredict
		case 'q':
			arg_quiet = 1;
			break;
			// print packetbl version
		case 'V':
			printf("%s\n", PACKAGE_VERSION);
			exit(EXIT_SUCCESS);
			break;
			// use a specific config file
		case 'f':
			packetbl_configfile = optarg;
			// check if the file exists
			if (access(packetbl_configfile, F_OK) == -1) {
				printf("The configuration file %s doesn't exist\n", packetbl_configfile);
				exit(EXIT_FAILURE);
			}
			break;
		case 'p':
			packetbl_pidfile = optarg;
			// check if the file exists
			if (access(packetbl_pidfile, F_OK) != -1) {
				printf("The pid file %s already exist\n",
				       packetbl_pidfile);
				exit(EXIT_FAILURE);
			}
			break;
			// add more debug level
		case 'd':
			arg_debug = atoi(optarg);
			break;
		case '?':
		default:
			print_help();
			exit(EXIT_FAILURE);
			break;
		}
	}

	return;
}

DOTCONF_CB(common_section_close)
{

	struct bl_context *context = (struct bl_context *) ctx;

	return context->current_end_token;
}

DOTCONF_CB(toggle_option)
{
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
	if (strcasecmp(cmd->name, "queueno") == 0) {
		if (cmd->data.value < 0) {
			logmsg(-1, LOG_ERR,
			       "Error parsing config: queueno cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		conf.queueno = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "queuesize") == 0) {
		if (cmd->data.value < 0) {
			logmsg(-1, LOG_ERR,
			       "Error parsing config: queuesize cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		conf.queue_size = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "quiet") == 0) {
		conf.quiet_bl = conf.quiet_wl = conf.quiet = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "quietwl") == 0) {
		conf.quiet_wl = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "quietbl") == 0) {
		conf.quiet_bl = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "loglevel") == 0) {
		if (cmd->data.value < 0) {
			logmsg(-1, LOG_ERR,
			       "Error parsing config: loglevel cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		if (cmd->data.value > 7) {
			logmsg(-1, LOG_ERR,
			       "Error parsing config: loglevel cannot be greater than 7\n");
			exit(EXIT_FAILURE);
		}
		conf.log_level = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "threadmax") == 0) {
		if (cmd->data.value < 0) {
			logmsg(-1, LOG_ERR,
			       "Error parsing config: threadmax cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		conf.threads_max = cmd->data.value;
		return NULL;
	}
	if (strcasecmp(cmd->name, "alternativedomain") == 0) {
		size_t sizechain = 0;
		conf.alt_domain = (char *) strdup(cmd->data.str);
		sizechain = strlen(conf.alt_domain);
		if (conf.alt_domain[sizechain - 1] == '.') {
			conf.alt_domain[sizechain - 1] = '\0';
		}
		return NULL;
	}
	if (strcasecmp(cmd->name, "alternativeresolvefile") == 0) {
		size_t sizechain = 0;
		conf.alt_resolv_file = (char *) strdup(cmd->data.str);
		sizechain = strlen(conf.alt_resolv_file);
		if (conf.alt_resolv_file[sizechain - 1] == '.') {
			conf.alt_resolv_file[sizechain - 1] = '\0';
		}
		return NULL;
	}

	if (strcasecmp(cmd->name, "cachettl") == 0) {
#ifdef USE_CACHE
		if (cmd->data.value < 0) {
			logmsg(0, LOG_ERR,
			       "Error parsing config: cachettl cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		packet_cache_ttl = cmd->data.value;
#else
		logmsg(0, LOG_ERR,
		       "Ignoring cache parameter, it is compiled without cache ouption\n");
#endif
		return NULL;
	}
	if (strcasecmp(cmd->name, "cachesize") == 0) {
#ifdef USE_CACHE
		if (cmd->data.value < 0) {
			logmsg(0, LOG_ERR,
			       "Error parsing config: cachelen cannot be a negative value\n");
			exit(EXIT_FAILURE);
		}
		packet_cache_len = cmd->data.value;
#else
		logmsg(0, LOG_ERR,
		       "Ignoring cache parameter, it is compiled without cache ouption\n");
#endif
		return NULL;
	}

	return NULL;
}

DOTCONF_CB(facility_option)
{

	if (strcasecmp(cmd->data.str, "auth") == 0) {
		conf.log_facility = LOG_AUTH;
	}
	else if (strcasecmp(cmd->data.str, "authpriv") == 0) {
		conf.log_facility = LOG_AUTHPRIV;
	}
	else if (strcasecmp(cmd->data.str, "cron") == 0) {
		conf.log_facility = LOG_CRON;
	}
	else if (strcasecmp(cmd->data.str, "daemon") == 0) {
		conf.log_facility = LOG_DAEMON;
	}
	else if (strcasecmp(cmd->data.str, "kern") == 0) {
		conf.log_facility = LOG_KERN;
	}
	else if (strcasecmp(cmd->data.str, "lpr") == 0) {
		conf.log_facility = LOG_LPR;
	}
	else if (strcasecmp(cmd->data.str, "mail") == 0) {
		conf.log_facility = LOG_MAIL;
	}
	else if (strcasecmp(cmd->data.str, "news") == 0) {
		conf.log_facility = LOG_NEWS;
	}
	else if (strcasecmp(cmd->data.str, "syslog") == 0) {
		conf.log_facility = LOG_SYSLOG;
	}
	else if (strcasecmp(cmd->data.str, "user") == 0) {
		conf.log_facility = LOG_USER;
	}
	else if (strcasecmp(cmd->data.str, "uucp") == 0) {
		conf.log_facility = LOG_UUCP;
	}
	else if (strcasecmp(cmd->data.str, "local0") == 0) {
		conf.log_facility = LOG_LOCAL0;
	}
	else if (strcasecmp(cmd->data.str, "local1") == 0) {
		conf.log_facility = LOG_LOCAL1;
	}
	else if (strcasecmp(cmd->data.str, "local2") == 0) {
		conf.log_facility = LOG_LOCAL2;
	}
	else if (strcasecmp(cmd->data.str, "local3") == 0) {
		conf.log_facility = LOG_LOCAL3;
	}
	else if (strcasecmp(cmd->data.str, "local4") == 0) {
		conf.log_facility = LOG_LOCAL4;
	}
	else if (strcasecmp(cmd->data.str, "local5") == 0) {
		conf.log_facility = LOG_LOCAL5;
	}
	else if (strcasecmp(cmd->data.str, "local6") == 0) {
		conf.log_facility = LOG_LOCAL6;
	}
	else if (strcasecmp(cmd->data.str, "local7") == 0) {
		conf.log_facility = LOG_LOCAL7;
	}
	else {
		logmsg(0, LOG_ERR, "Log facility %s is invalid\n",
		       cmd->data.str);
		exit(EXIT_FAILURE);
	}

	return NULL;
}

DOTCONF_CB(common_option)
{

	struct config_entry *ce, *tmp = NULL;
#ifdef HAVE_FIREDNS
	size_t sizechain = 0;
#endif

	ce = malloc(sizeof(struct config_entry));
	if (ce == NULL) {
		return NULL;
	}

	ce->string = (char *) strdup(cmd->data.str);
	ce->next = NULL;

	if (strcasecmp(cmd->name, "name") == 0) {
		size_t sizechain = 0;
		conf.name = (char *) strdup(cmd->data.str);
		sizechain = strlen(conf.name);
		if (conf.name[sizechain - 1] == '.') {
			conf.name[sizechain - 1] = '\0';
		}
		return NULL;
	}

	if (strcasecmp(cmd->name, "blacklistbl") == 0) {

#ifdef HAVE_FIREDNS
		sizechain = strlen(ce->string);
		if (ce->string[sizechain - 1] == '.') {
			ce->string[sizechain - 1] = '\0';
		}
#endif

		/* resolution check completely removed.  Will put it back
		 * during config file and architectural revamp. */
		if (blacklistbl == NULL) {
			blacklistbl = ce;
			return NULL;
		}
		else {
			tmp = blacklistbl;
		}
	}

	if (strcasecmp(cmd->name, "whitelistbl") == 0) {

#ifdef HAVE_FIREDNS
		sizechain = strlen(ce->string);
		if (ce->string[sizechain - 1] == '.') {
			ce->string[sizechain - 1] = '\0';
		}
#endif

		/* resolution check completely removed.  Will put it back
		 * during config file and architectural revamp. */
		if (whitelistbl == NULL) {
			whitelistbl = ce;
			return NULL;
		}
		else {
			tmp = whitelistbl;
		}
	}

	if (strcasecmp(cmd->name, "whitelist") == 0) {
		if (parse_cidr(ce) == -1) {
			fprintf(stderr,
				"Error parsing CIDR in %s, ignoring\n",
				ce->string);
			free(ce->string);
			free(ce);
			return NULL;
		}
		if (whitelist == NULL) {
			whitelist = ce;
			return NULL;
		}
		else {
			tmp = whitelist;
		}
	}

	if (strcasecmp(cmd->name, "blacklist") == 0) {
		if (parse_cidr(ce) == -1) {
			fprintf(stderr,
				"Error parsing CIDR in %s, ignoring\n",
				ce->string);
			free(ce->string);
			free(ce);
			return NULL;
		}
		if (blacklist == NULL) {
			blacklist = ce;
			return NULL;
		}
		else {
			tmp = blacklist;
		}
	}

	while (tmp->next != NULL) {
		tmp = tmp->next;
	}

	tmp->next = ce;

	return NULL;

}

DOTCONF_CB(host_section_open)
{

	struct bl_context *context = (struct bl_context *) ctx;
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
int
parse_cidr(struct config_entry *ce)
{

	int sep = 0;		// which separator we're on.
	char *counter, *c1;
	char number[BUFFERSIZE];

	if (ce == NULL) {
		return -1;
	}

	c1 = ce->string;	// initialize state counter

	for (counter = ce->string;
	     (counter - ce->string) < (int) strlen(ce->string); counter++) {
		switch (*counter) {
		case '.':
		case '/':
			// separator
			strncpy(number, c1, (int) (counter - c1));
			number[(int) (counter - c1)] = '\0';
			switch (sep) {
			case 0:
				ce->ip.s_ip_b1 = atoi(number);
				if ((ce->ip.s_ip_b1 - 0) < 0 ||
				    ce->ip.s_ip_b1 > 255) {
					return -1;
				}
				break;
			case 1:
				ce->ip.s_ip_b2 = atoi(number);
				if ((ce->ip.s_ip_b2 - 0) < 0 ||
				    ce->ip.s_ip_b2 > 255) {
					return -1;
				}
				break;
			case 2:
				ce->ip.s_ip_b3 = atoi(number);
				if ((ce->ip.s_ip_b3 - 0) < 0 ||
				    ce->ip.s_ip_b3 > 255) {
					return -1;
				}
				break;
			case 3:
				ce->ip.s_ip_b4 = atoi(number);
				if ((ce->ip.s_ip_b4 - 0) < 0 ||
				    ce->ip.s_ip_b4 > 255) {
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
	strncpy(number, c1, (int) (counter - c1));
	number[(int) (counter - c1)] = '\0';
	ce->cidr.network = atoi(number);

	ce->cidr.processed = 0;
	ce->cidr.processed = 0xffffffff << (32 - ce->cidr.network);

	ce->cidr.ip = 0;
	ce->cidr.ip = ce->ip.s_ip_b1 << 24;
	ce->cidr.ip |= ce->ip.s_ip_b2 << 16;
	ce->cidr.ip |= ce->ip.s_ip_b3 << 8;
	ce->cidr.ip |= ce->ip.s_ip_b4;

	/* Mask out the bits that aren't in the network in cidr.ip.
	 * We don't care about them and they'll just confuse the issue. */
	ce->cidr.ip &= ce->cidr.processed;

	return 0;

}


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
int
check_packet_dnsbl(const struct packet_info *ip, struct config_entry *list)
{

	struct config_entry *wltmp = NULL;
#ifdef	HAVE_FIREDNS
	struct in_addr *host;
#else
	struct hostent *host;
#endif

	// Set time, for debug
	double start_req = 0, end_req;
	if (conf.debug > 0) {
		start_req = cur_time();
	}

	if (ip == NULL || list == NULL) {
		return 0;
	}

	wltmp = list;

	// Creating resolvers
	ldns_resolver *res_opt = NULL;
	ldns_resolver *res_def = NULL;
	if (conf.alt_domain && conf.alt_resolv_file) {
		configure_direct_nameserver(&res_opt, conf.alt_resolv_file);
		if (res_opt == NULL) {
			logmsg(0, LOG_ERR,
			       "Create optional nameservers failed");
			return 0;
		}
		configure_direct_nameserver(&res_def, NULL);
		if (res_def == NULL) {
			logmsg(0, LOG_ERR,
			       "Create default nameservers failed");
			return 0;
		}
	}


	while (1) {

		char lookupbuf[BUFFERSIZE];

		snprintf(lookupbuf, sizeof(lookupbuf),
			 "%hhu.%hhu.%hhu.%hhu.%s", ip->s_ip_b4, ip->s_ip_b3,
			 ip->s_ip_b2, ip->s_ip_b1, wltmp->string);


		if (regexec(&regex, wltmp->string, (size_t) 0, NULL, 0) !=
		    REG_NOMATCH) {
			logmsg(1, LOG_DEBUG, "Sending to optional DNS");

			if (dns_query(res_opt, lookupbuf)) {
				// found
				snprintf(rulemsgbuf, sizeof(rulemsgbuf), "%s",
					 (strlen(wltmp->string) <
					  sizeof(rulemsgbuf)) ? wltmp->
					 string : "-");
				if (conf.debug > 1) {
					end_req = cur_time();
					logmsg(1, LOG_DEBUG,
					       "finish tread, thread time (%.3f sec)",
					       (end_req -
						start_req) / 1000000.0);
				}
				ldns_resolver_deep_free(res_opt);
				ldns_resolver_deep_free(res_def);
				return 1;
			}
		}
		else {

			logmsg(-1, LOG_DEBUG, "Sending to default DNS");
#ifndef HAVE_FIREDNS
			if (!dns_query(res_def, lookupbuf)) {
#else
			host = firedns_resolveip4(lookupbuf);
			if (host == NULL) {
#endif
				;
			}
			else {
				// found.
				snprintf(rulemsgbuf, sizeof(rulemsgbuf), "%s",
					 (strlen(wltmp->string) <
					  sizeof(rulemsgbuf)) ? wltmp->
					 string : "-");
				if (conf.debug > 1) {
					end_req = cur_time();
					logmsg(1, LOG_DEBUG,
					       "finish tread, thread time (%.3f sec)",
					       (end_req -
						start_req) / 1000000.0);
				}
				ldns_resolver_deep_free(res_opt);
				ldns_resolver_deep_free(res_def);
				return 1;
			}
		}

		if (wltmp->next == NULL) {
			/* Termination case */
			if (conf.debug > 1) {
				end_req = cur_time();
				logmsg(1, LOG_DEBUG,
				       "finish tread, thread time (%.3f sec)",
				       (end_req - start_req) / 1000000.0);
			}
			ldns_resolver_deep_free(res_opt);
			ldns_resolver_deep_free(res_def);
			return 0;
		}

		wltmp = wltmp->next;
	}
	if (conf.debug > 1) {
		end_req = cur_time();
		logmsg(1, LOG_DEBUG, "finish tread, thread time (%.3f sec)",
		       (end_req - start_req) / 1000000.0);
	}

	ldns_resolver_deep_free(res_opt);
	ldns_resolver_deep_free(res_def);
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
int
check_packet_list(const struct packet_info *ip, struct config_entry *list)
{

	struct config_entry *wltmp = NULL;
	uint32_t ip_proc = 0;


	if (ip == NULL || list == NULL) {
		return 0;
	}

	ip_proc = ip->s_ip_b1 << 24;
	ip_proc |= ip->s_ip_b2 << 16;
	ip_proc |= ip->s_ip_b3 << 8;
	ip_proc |= ip->s_ip_b4;

	wltmp = list;

	while (1) {
		uint32_t p = 0;
		p = ip_proc;
		p &= wltmp->cidr.processed;

		if (p == wltmp->cidr.ip) {
			snprintf(rulemsgbuf, sizeof(rulemsgbuf), "%s",
				 wltmp->string);
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
static void
get_ip_string(const struct packet_info *ip)
{

	if (ip == NULL) {
		sprintf(ipmsgbuf, "-");
		return;
	}

	snprintf(ipmsgbuf, sizeof(ipmsgbuf),
		 "%hhu.%hhu.%hhu.%hhu:%d-%hhu.%hhu.%hhu.%hhu:%d", ip->s_ip_b1,
		 ip->s_ip_b2, ip->s_ip_b3, ip->s_ip_b4, ip->s_port,
		 ip->d_ip_b1, ip->d_ip_b2, ip->d_ip_b3, ip->d_ip_b4,
		 ip->d_port);
	return;
}
