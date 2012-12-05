/* Copyright (C) 2005, 2006 by Eugene Kurmanin <me@kurmanin.info>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef _REENTRANT
#error Compile with -D_REENTRANT flag
#endif

#include <arpa/inet.h>
#if __linux__ || __sun__
#include <arpa/nameser.h>
#else
#include <bind/arpa/nameser.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#ifndef __sun__
#include <getopt.h>
#endif
#include <grp.h>
#include <libmilter/mfapi.h>
#if __linux__ || __sun__
#include <netdb.h>
#else
#include <bind/netdb.h>
#endif
#include <netinet/in.h>
#include <pthread.h>
#include <pwd.h>
#include <regex.h>
#if __linux__ || __sun__
#include <resolv.h>
#else
#include <bind/resolv.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL		0
#endif

#define SAFE_FREE(x)		if (x) { free(x); x = NULL; }

#define hash_size(x)		((unsigned long) 1 << x)
#define hash_mask(x)		(hash_size(x) - 1)

#define CONFIG_FILE		"/etc/mail/smfs/smf-sav.conf"
#define PUBLIC_NAME		"yourhost.yourdomain.tld"
#define SAFE_CALLBACK		"postmaster@yourdomain.tld"
#define SYSLOG_FACILITY		LOG_MAIL
#define SAV			1
#define IGNORE_TEMPFAIL		0
#define BLOCK_IGNORANTS		0
#define FROM_PASS_TTL		86400
#define FROM_TEMPFAIL_TTL	300
#define FROM_FAIL_TTL		3600
#define TO_PASS_TTL		3600
#define TO_TEMPFAIL_TTL		300
#define TO_FAIL_TTL		3600
#define WORK_SPACE		"/var/run/smfs"
#define OCONN			"unix:" WORK_SPACE "/smf-sav.sock"
#define USER			"smfs"

#define DNS_RETRANS		7
#define DNS_RETRY		4
#define SMTP_PORT		25
#define CONN_TIMEOUT		60
#define SEND_TIMEOUT		60
#define RECV_TIMEOUT		120
#define SLOW_DOWN_SLICE		5

#define MAXLINE			128
#define MAXMX			16
#define MXBUFFER		(128 * MAXMX)
#define MAXPACKET		8192

#define QUIT_OK			1
#define QUIT_PERM		0
#define QUIT_FAIL		-1

#define SMTP_CMD_OK(x)		(200 <= (x) && (x) < 300)
#define SMTP_CMD_PERM(x)	(500 <= (x) && (x) < 600)

#define CALLBACK		"<>"
#define HASH_POWER		16
#define FACILITIES_AMOUNT	10
#define IPV4_DOT_DECIMAL	"^[0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.][0-9]{1,3}[.]?$"

#ifdef __sun__
int daemon(int nochdir, int noclose) {
    pid_t pid;
    int fd = 0;

    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if ((pid = setsid()) == -1) {
	fprintf(stderr, "setsid: %s\n", strerror(errno));
	return 1;
    }
    if ((pid = fork()) < 0) {
	fprintf(stderr, "fork: %s\n", strerror(errno));
	return 1;
    }
    else
	if (pid > 0) _exit(0);
    if (!nochdir && chdir("/")) {
	fprintf(stderr, "chdir: %s\n", strerror(errno));
	return 1;
    }
    if (!noclose) {
	dup2(fd, fileno(stdout));
	dup2(fd, fileno(stderr));
	dup2(open("/dev/null", O_RDONLY, 0), fileno(stdin));
    }
    return 0;
}
#endif

typedef enum cache_put_mode {
    CACHE_KEEP = 0,
    CACHE_OVER
} cache_put_mode;

typedef enum cache_item_type {
    SENDERS = 0,
    RECIPIENTS
} cache_item_type;

typedef enum cache_item_status {
    ST_NONE = 0,
    SENDER_PASS,
    SENDER_FAIL,
    SENDER_TEMPFAIL,
    RECIPIENT_PASS,
    RECIPIENT_FAIL,
    RECIPIENT_TEMPFAIL
} cache_item_status;

typedef struct cache_item {
    char *item;
    unsigned long hash;
    cache_item_type type;
    cache_item_status status;
    time_t exptime;
    struct cache_item *next;
} cache_item;

typedef struct CIDR {
    unsigned long ip;
    unsigned short int mask;
    struct CIDR *next;
} CIDR;

typedef struct STR {
    char *str;
    struct STR *next;
} STR;

typedef struct config {
    char *public_name;
    char *safe_callback;
    char *mail_store;
    char *run_as_user;
    char *sendmail_socket;
    CIDR *cidrs;
    STR *ptrs;
    STR *froms;
    STR *tos;
    int syslog_facility;
    int sav;
    int ignore_tempfail;
    int block_ignorants;
    unsigned long from_pass_ttl;
    unsigned long from_tempfail_ttl;
    unsigned long from_fail_ttl;
    unsigned long to_pass_ttl;
    unsigned long to_tempfail_ttl;
    unsigned long to_fail_ttl;
} config;

typedef struct facilities {
    char *name;
    int facility;
} facilities;

typedef union {
    HEADER hdr;
    unsigned char buf[MAXPACKET];
} querybuf;

static regex_t re_ipv4;
static cache_item **cache = NULL;
static const char *config_file = CONFIG_FILE;
static config conf;
static pthread_mutex_t cache_mutex;
static facilities syslog_facilities[] = {
    { "daemon", LOG_DAEMON },
    { "mail", LOG_MAIL },
    { "local0", LOG_LOCAL0 },
    { "local1", LOG_LOCAL1 },
    { "local2", LOG_LOCAL2 },
    { "local3", LOG_LOCAL3 },
    { "local4", LOG_LOCAL4 },
    { "local5", LOG_LOCAL5 },
    { "local6", LOG_LOCAL6 },
    { "local7", LOG_LOCAL7 }
};

struct context {
    char addr[64];
    char fqdn[MAXLINE];
    char from[MAXLINE];
    char sender[MAXLINE];
    char rcpt[MAXLINE];
    char recipient[MAXLINE];
    int slowdown;
};

static sfsistat smf_connect(SMFICTX *, char *, _SOCK_ADDR *);
static sfsistat smf_envfrom(SMFICTX *, char **);
static sfsistat smf_envrcpt(SMFICTX *, char **);
static sfsistat smf_eoh(SMFICTX *ctx);
static sfsistat smf_close(SMFICTX *);

static void strscpy(register char *dst, register const char *src, size_t size) {
    register size_t i;

    for (i = 0; i < size && (dst[i] = src[i]) != 0; i++) continue;
    dst[i] = '\0';
}

static void strtolower(register char *str) {

    for (; *str; str++)
	if (isascii(*str) && isupper(*str)) *str = tolower(*str);
}

static unsigned long translate(char *value) {
    unsigned long unit;
    size_t len = strlen(value);

    switch (value[len - 1]) {
	case 'm':
	case 'M':
	    unit = 60;
	    value[len - 1] = '\0';
	    break;
	case 'h':
	case 'H':
	    unit = 3600;
	    value[len - 1] = '\0';
	    break;
	case 'd':
	case 'D':
	    unit = 86400;
	    value[len - 1] = '\0';
	    break;
	default:
	    return atol(value);
    }
    return (atol(value) * unit);
}

static unsigned long hash_code(register const unsigned char *key) {
    register unsigned long hash = 0;
    register size_t i, len = strlen(key);

    for (i = 0; i < len; i++) {
	hash += key[i];
	hash += (hash << 10);
	hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);
    return hash;
}

static int cache_init(void) {

    if (!(cache = calloc(1, hash_size(HASH_POWER) * sizeof(void *)))) return 0;
    return 1;
}

static void cache_destroy(void) {
    unsigned long i, size = hash_size(HASH_POWER);
    cache_item *it, *it_next;

    for (i = 0; i < size; i++) {
	it = cache[i];
	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->item);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    SAFE_FREE(cache);
}

static cache_item_status cache_get(const char *key, cache_item_type type) {
    unsigned long hash = hash_code(key);
    cache_item *it = cache[hash & hash_mask(HASH_POWER)];
    time_t curtime = time(NULL);

    while (it) {
	if (it->type == type && it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) return it->status;
	it = it->next;
    }
    return ST_NONE;
}

static void cache_put(const char *key, unsigned long ttl, cache_item_type type, cache_item_status status, cache_put_mode mode) {
    unsigned long hash = hash_code(key);
    time_t curtime = time(NULL);
    cache_item *it, *parent = NULL;

    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->type == type && it->hash == hash && it->exptime > curtime && it->item && !strcmp(key, it->item)) {
	    if (mode == CACHE_OVER) {
		it->status = status;
		it->exptime = curtime + ttl;
	    }
	    return;
	}
	it = it->next;
    }
    it = cache[hash & hash_mask(HASH_POWER)];
    while (it) {
	if (it->exptime < curtime) {
	    SAFE_FREE(it->item);
	    it->item = strdup(key);
	    it->hash = hash;
	    it->type = type;
	    it->status = status;
	    it->exptime = curtime + ttl;
	    return;
	}
	parent = it;
	it = it->next;
    }
    if ((it = (cache_item *) calloc(1, sizeof(cache_item)))) {
	it->item = strdup(key);
	it->hash = hash;
	it->type = type;
	it->status = status;
	it->exptime = curtime + ttl;
	if (parent)
	    parent->next = it;
	else
	    cache[hash & hash_mask(HASH_POWER)] = it;
    }
}

static void free_config(void) {

    SAFE_FREE(conf.public_name);
    SAFE_FREE(conf.safe_callback);
    SAFE_FREE(conf.mail_store);
    SAFE_FREE(conf.run_as_user);
    SAFE_FREE(conf.sendmail_socket);
    if (conf.cidrs) {
	CIDR *it = conf.cidrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    if (conf.ptrs) {
	STR *it = conf.ptrs, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    if (conf.froms) {
	STR *it = conf.froms, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
    if (conf.tos) {
	STR *it = conf.tos, *it_next;

	while (it) {
	    it_next = it->next;
	    SAFE_FREE(it->str);
	    SAFE_FREE(it);
	    it = it_next;
	}
    }
}

static int load_config(void) {
    FILE *fp;
    char buf[2 * MAXLINE];

    conf.public_name = strdup(PUBLIC_NAME);
    conf.safe_callback = strdup(SAFE_CALLBACK);
    conf.run_as_user = strdup(USER);
    conf.sendmail_socket = strdup(OCONN);
    conf.syslog_facility = SYSLOG_FACILITY;
    conf.sav = SAV;
    conf.ignore_tempfail = IGNORE_TEMPFAIL;
    conf.block_ignorants = BLOCK_IGNORANTS;
    conf.from_pass_ttl = FROM_PASS_TTL;
    conf.from_tempfail_ttl = FROM_TEMPFAIL_TTL;
    conf.from_fail_ttl = FROM_FAIL_TTL;
    conf.to_pass_ttl = TO_PASS_TTL;
    conf.to_tempfail_ttl = TO_TEMPFAIL_TTL;
    conf.to_fail_ttl = TO_FAIL_TTL;
    if (!(fp = fopen(config_file, "r"))) return 0;
    while (fgets(buf, sizeof(buf) - 1, fp)) {
	char key[MAXLINE];
	char val[MAXLINE];
	char *p = NULL;

	if ((p = strchr(buf, '#'))) *p = '\0';
	if (!(strlen(buf))) continue;
	if (sscanf(buf, "%127s %127s", key, val) != 2) continue;
	if (!strcasecmp(key, "whitelistip")) {
	    char *slash = NULL;
	    unsigned short int mask = 32;

	    if ((slash = strchr(val, '/'))) {
		*slash = '\0';
		if ((mask = atoi(++slash)) > 32) mask = 32;
	    }
	    if (val[0] && !regexec(&re_ipv4, val, 0, NULL, 0)) {
		CIDR *it = NULL;
		unsigned long ip;

		if ((ip = inet_addr(val)) == 0xffffffff) continue;
		if (!conf.cidrs)
		    conf.cidrs = (CIDR *) calloc(1, sizeof(CIDR));
		else
		    if ((it = (CIDR *) calloc(1, sizeof(CIDR)))) {
			it->next = conf.cidrs;
			conf.cidrs = it;
		    }
		if (conf.cidrs) {
		    conf.cidrs->ip = ip;
		    conf.cidrs->mask = mask;
		}
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistptr")) {
	    STR *it = NULL;

	    if (!conf.ptrs)
		conf.ptrs = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.ptrs;
		    conf.ptrs = it;
		}
	    if (conf.ptrs && !conf.ptrs->str) conf.ptrs->str = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "whitelistfrom")) {
	    STR *it = NULL;

	    if (!conf.froms)
		conf.froms = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.froms;
		    conf.froms = it;
		}
	    if (conf.froms && !conf.froms->str) {
		strtolower(val);
		conf.froms->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "whitelistto")) {
	    STR *it = NULL;

	    if (!conf.tos)
		conf.tos = (STR *) calloc(1, sizeof(STR));
	    else
		if ((it = (STR *) calloc(1, sizeof(STR)))) {
		    it->next = conf.tos;
		    conf.tos = it;
		}
	    if (conf.tos && !conf.tos->str) {
		strtolower(val);
		conf.tos->str = strdup(val);
	    }
	    continue;
	}
	if (!strcasecmp(key, "publicname")) {
	    SAFE_FREE(conf.public_name);
	    conf.public_name = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "safecallback")) {
	    SAFE_FREE(conf.safe_callback);
	    conf.safe_callback = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "sav") && !strcasecmp(val, "off")) {
	    conf.sav = 0;
	    continue;
	}
	if (!strcasecmp(key, "ignoretempfail") && !strcasecmp(val, "on")) {
	    conf.ignore_tempfail = 1;
	    continue;
	}
	if (!strcasecmp(key, "blockignorants") && !strcasecmp(val, "on")) {
	    conf.block_ignorants = 1;
	    continue;
	}
	if (!strcasecmp(key, "mailstore")) {
	    SAFE_FREE(conf.mail_store);
	    conf.mail_store = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "frompassttl")) {
	    conf.from_pass_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "fromtfailttl")) {
	    conf.from_tempfail_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "fromfailttl")) {
	    conf.from_fail_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "topassttl")) {
	    conf.to_pass_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "totfailttl")) {
	    conf.to_tempfail_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "tofailttl")) {
	    conf.to_fail_ttl = translate(val);
	    continue;
	}
	if (!strcasecmp(key, "user")) {
	    SAFE_FREE(conf.run_as_user);
	    conf.run_as_user = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "socket")) {
	    SAFE_FREE(conf.sendmail_socket);
	    conf.sendmail_socket = strdup(val);
	    continue;
	}
	if (!strcasecmp(key, "syslog")) {
	    int i;

	    for (i = 0; i < FACILITIES_AMOUNT; i++)
		if (!strcasecmp(val, syslog_facilities[i].name))
		    conf.syslog_facility = syslog_facilities[i].facility;
	    continue;
	}
    }
    fclose(fp);
    return 1;
}

static int ip_cidr(const unsigned long ip, const short int mask, const unsigned long checkip) {
    unsigned long ipaddr = 0;
    unsigned long cidrip = 0;
    unsigned long subnet = 0;

    subnet = ~0;
    subnet = subnet << (32 - mask);
    cidrip = htonl(ip) & subnet;
    ipaddr = ntohl(checkip) & subnet;
    if (cidrip == ipaddr) return 1;
    return 0;
}

static int ip_check(const unsigned long checkip) {
    CIDR *it = conf.cidrs;

    while (it) {
	if (ip_cidr(it->ip, it->mask, checkip)) return 1;
	it = it->next;
    }
    return 0;
}

static int ptr_check(const char *ptr) {
    STR *it = conf.ptrs;

    while (it) {
	if (it->str && strcasestr(ptr, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int from_check(const char *from) {
    STR *it = conf.froms;

    while (it) {
	if (it->str && strstr(from, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static int to_check(const char *to) {
    STR *it = conf.tos;

    while (it) {
	if (it->str && strstr(to, it->str)) return 1;
	it = it->next;
    }
    return 0;
}

static void time_humanize(register char *dst, time_t tm) {
    register int h, m, s;

    h = tm / 3600;
    tm = tm % 3600;
    m = tm / 60;
    tm = tm % 60;
    s = tm;
    snprintf(dst, 10, "%02d:%02d:%02d", h, m, s);
}

static int address_preparation(register char *dst, register const char *src) {
    register const char *start = NULL, *stop = NULL;
    int tail;

    if (!(start = strchr(src, '<'))) return 0;
    if (!(stop = strrchr(src, '>'))) return 0;
    if (++start >= --stop) return 0;
    strscpy(dst, start, stop - start + 1);
    tail = strlen(dst) - 1;
    if ((dst[0] >= 0x07 && dst[0] <= 0x0d) || dst[0] == 0x20) return 0;
    if ((dst[tail] >= 0x07 && dst[tail] <= 0x0d) || dst[tail] == 0x20) return 0;
    if (!strchr(dst, '@')) return 0;
    return 1;
}

static void do_sleep(int sec) {
    struct timeval req;
    int ret = 0;

    req.tv_sec = sec;
    req.tv_usec = 0;
    do {
	ret = select(0, NULL, NULL, NULL, &req);
    } while (ret < 0 && errno == EINTR);
}

static void die(const char *reason) {

    syslog(LOG_ERR, "[ERROR] die: %s", reason);
    smfi_stop();
    do_sleep(60);
    abort();
}

static void mutex_lock(pthread_mutex_t *mutex) {

    if (pthread_mutex_lock(mutex)) die("pthread_mutex_lock");
}

static void mutex_unlock(pthread_mutex_t *mutex) {

    if (pthread_mutex_unlock(mutex)) die("pthread_mutex_unlock");
}

static int block_socket(int sock, int block) {
    int flags;

    if (sock < 0) return -1;
    if ((flags = fcntl(sock, F_GETFL)) < 0) return -1;
    if (block)
	flags &= ~O_NONBLOCK;
    else
	flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0) return -1;
    return 0;
}

static void close_socket(int sock) {
    int ret;

    if (sock < 0) return;
    shutdown(sock, SHUT_RDWR);
    do {
	ret = close(sock);
    } while (ret < 0 && errno == EINTR);
}

static int smtp_send(int sock, const char *buffer) {
    int ret;
    fd_set wfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = SEND_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    do {
	ret = send(sock, buffer, strlen(buffer), MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret < strlen(buffer)) return -1;
    return 0;
}

static int smtp_recv(int sock, char *buffer, int size) {
    int ret;
    fd_set rfds;
    struct timeval tv;

    if (sock < 0) return -1;
    do {
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	tv.tv_sec = RECV_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, &rfds, NULL, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &rfds)) return -1;
    do {
	ret = recv(sock, buffer, size - 1, MSG_NOSIGNAL);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    return 0;
}

static int smtp_connect(int sock, struct sockaddr *address, int addrlen) {
    int optval, ret;
    fd_set wfds;
    struct timeval tv;
    socklen_t optlen = sizeof(optval);

    if (sock < 0) return -1;
    if (block_socket(sock, 0) < 0) return -1;
    if ((ret = connect(sock, address, addrlen)) < 0)
	if (errno != EINPROGRESS) return -1;
    if (ret == 0) goto done;
    do {
	FD_ZERO(&wfds);
	FD_SET(sock, &wfds);
	tv.tv_sec = CONN_TIMEOUT;
	tv.tv_usec = 0;
	ret = select(sock + 1, NULL, &wfds, NULL, &tv);
    } while (ret < 0 && errno == EINTR);
    if (ret <= 0) return -1;
    if (!FD_ISSET(sock, &wfds)) return -1;
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &optval, &optlen) < 0) return -1;
    if (optval) return -1;
done:
    if (block_socket(sock, 1) < 0) return -1;
    return 0;
}

static int get_smtp_response(const char *buffer) {
    int ret = 0;

    if (strlen(buffer) < 4) return -1;
    sscanf(buffer, "%3d", &ret);
    return ret;
}

static int smtp_chat(int sock, const char *cmd) {
    int ret;
    char *buffer = NULL;
    char *lastline;

    if (sock < 0) return -1;
    if (cmd && smtp_send(sock, cmd) < 0) return -1;

    if (!(buffer = calloc(1, 8192))) {
        return -1;
    }

    do {

    if (smtp_recv(sock, buffer, 8192) < 0) {
        free(buffer);
        return -1;
    }

    // If reply is split onto more TCP packets, read until newline reached

    while (buffer[strlen(buffer)-1]!='\n' && strlen(buffer)<8100) {
       if (smtp_recv(sock, (char *)(buffer+strlen(buffer)), 8191-strlen(buffer)) < 0) {
          free(buffer);
          return -1;
          }
    }

    // if multiline reply, we are only interested in the last line

    if (buffer[strlen(buffer)-1]=='\n')
       buffer[strlen(buffer)-1]=0;

    if ((lastline=strrchr(buffer,'\n'))==NULL)
       lastline=buffer;

    // If multiline reply, reading next paket if last line isn't last line
    }
    while (lastline[3]=='-');

    ret = get_smtp_response(buffer);
    free(buffer);
    return ret;
}

static void smtp_quit(int sock) {
    char cmd[8];

    if (sock < 0) return;
    strscpy(cmd, "RSET\r\n", sizeof(cmd) - 1);
    if (smtp_chat(sock, cmd) <= 0) return;
    strscpy(cmd, "QUIT\r\n", sizeof(cmd) - 1);
    smtp_chat(sock, cmd);
}

static int mailer(const char *rcpt, const char *mxhost) {
    struct sockaddr_in address;
    char cmd[MAXLINE];
    char ipaddr[MAXLINE];
    int sock, ret;
    int optval = 1;
    socklen_t optlen = sizeof(optval);

    memset(&address, 0, sizeof(address));
    if (!regexec(&re_ipv4, mxhost, 0, NULL, 0)) {
	char host[32];

	strscpy(host, mxhost, sizeof(host) - 1);
	if (host[strlen(host) - 1] == '.') host[strlen(host) - 1] = '\0';
	address.sin_addr.s_addr = inet_addr(host);
    }
    else {
	struct addrinfo *ai = NULL;
	struct addrinfo hints;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	if (getaddrinfo(mxhost, NULL, &hints, &ai)) {
	    if (ai) freeaddrinfo(ai);
	    return QUIT_FAIL;
	}
	address.sin_addr.s_addr = *(uint32_t *) &((struct sockaddr_in *)ai->ai_addr)->sin_addr;
	freeaddrinfo(ai);
    }
    
    snprintf(ipaddr,MAXLINE,"%u.%u.%u.%u",
             (address.sin_addr.s_addr&0x000000ff)>>0,
             (address.sin_addr.s_addr&0x0000ff00)>>8,
             (address.sin_addr.s_addr&0x00ff0000)>>16,
             (address.sin_addr.s_addr&0xff000000)>>24);
	     
    syslog(LOG_INFO, "MX check at %s [%s]",mxhost,ipaddr);	
        
    if (address.sin_addr.s_addr == 0x0100007f || address.sin_addr.s_addr == 0xffffffff) return QUIT_FAIL;
    if (conf.mail_store && strcmp(ipaddr,conf.mail_store)==0) return QUIT_OK;
    address.sin_family = AF_INET;
    address.sin_port = htons(SMTP_PORT);
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if (sock < 0) return QUIT_FAIL;
    if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
    if (smtp_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) goto quit_fail;
    if ((ret = smtp_chat(sock, NULL)) <= 0) goto quit_fail;
    if (SMTP_CMD_PERM(ret)) goto quit_perm;
    if (!SMTP_CMD_OK(ret)) goto quit_temp;
    snprintf(cmd, sizeof(cmd), "HELO %s\r\n", conf.public_name);
    if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
    if (SMTP_CMD_PERM(ret)) goto quit_perm;
    if (!SMTP_CMD_OK(ret)) goto quit_temp;
    snprintf(cmd, sizeof(cmd), "MAIL FROM:%s\r\n", CALLBACK);
    if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
    if (conf.block_ignorants && SMTP_CMD_PERM(ret)) goto quit_perm;
    if (SMTP_CMD_PERM(ret) || !SMTP_CMD_OK(ret)) {
	strncpy(cmd, "RSET\r\n", sizeof(cmd) - 1);
	if ((ret = smtp_chat(sock, cmd)) <= 0) {
	   // Probably lost connection, trying to reconnect
           close_socket(sock);

           // Reconnecting for next try, because RSET didn't work
           sock = socket(PF_INET, SOCK_STREAM, 0);
           if (sock < 0) return QUIT_FAIL;
           if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
           if (smtp_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
	      goto quit_fail;
	      }
	   
           if ((ret = smtp_chat(sock, NULL)) <= 0) goto quit_fail;
           if (SMTP_CMD_PERM(ret)) goto quit_perm;
           if (!SMTP_CMD_OK(ret)) goto quit_temp;
           snprintf(cmd, sizeof(cmd), "HELO %s\r\n", conf.public_name);
           if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
	   }

	if (SMTP_CMD_PERM(ret)) goto quit_perm;
	if (!SMTP_CMD_OK(ret)) goto quit_temp;
	snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", conf.safe_callback);
	if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
	if (SMTP_CMD_PERM(ret)) goto quit_perm;
	if (!SMTP_CMD_OK(ret)) goto quit_temp;
    }

    snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", rcpt);
    if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
    if (conf.block_ignorants && SMTP_CMD_PERM(ret)) goto quit_perm;
    if (SMTP_CMD_PERM(ret) || !SMTP_CMD_OK(ret)) {
	strncpy(cmd, "RSET\r\n", sizeof(cmd) - 1);
	if ((ret = smtp_chat(sock, cmd)) <= 0) {
	   // Probably lost connection, trying to reconnect
           close_socket(sock);

           // Reconnecting for next try, because RSET didn't work
           sock = socket(PF_INET, SOCK_STREAM, 0);
           if (sock < 0) return QUIT_FAIL;
           if (setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &optval, optlen) < 0) goto quit_fail;
           if (smtp_connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
	      goto quit_fail;
	      }
	   
           if ((ret = smtp_chat(sock, NULL)) <= 0) goto quit_fail;
           if (SMTP_CMD_PERM(ret)) goto quit_perm;
           if (!SMTP_CMD_OK(ret)) goto quit_temp;
           snprintf(cmd, sizeof(cmd), "HELO %s\r\n", conf.public_name);
           if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
	   }

	if (SMTP_CMD_PERM(ret)) goto quit_perm;
	if (!SMTP_CMD_OK(ret)) goto quit_temp;
	snprintf(cmd, sizeof(cmd), "MAIL FROM:<%s>\r\n", conf.safe_callback);
	if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
	if (SMTP_CMD_PERM(ret)) goto quit_perm;
	if (!SMTP_CMD_OK(ret)) goto quit_temp;
	snprintf(cmd, sizeof(cmd), "RCPT TO:<%s>\r\n", rcpt);
	if ((ret = smtp_chat(sock, cmd)) <= 0) goto quit_fail;
	if (SMTP_CMD_PERM(ret)) goto quit_perm;
	if (!SMTP_CMD_OK(ret)) goto quit_temp;
    }
    smtp_quit(sock);
    close_socket(sock);
    return QUIT_OK;
quit_temp:
    smtp_quit(sock);
    close_socket(sock);
    return QUIT_FAIL;
quit_perm:
    smtp_quit(sock);
    close_socket(sock);
    return QUIT_PERM;
quit_fail:
    close_socket(sock);
    return QUIT_FAIL;
}



static int get_mx_rr(const char *host, char *MXHostBuf, char **mxhosts, querybuf *answer) {
    unsigned char *eom, *cp;
    unsigned short pref, type, prefs[MAXMX];
    int i, j, n, ttl, ancount, qdcount, buflen, weight[MAXMX], nmx = 0;
    char *bp;
    HEADER *hp;
    struct __res_state res_status;

    memset(&res_status, 0, sizeof(res_status));
    if (res_ninit(&res_status) < 0) return -1;
    res_status.retrans = DNS_RETRANS;
    res_status.retry = DNS_RETRY;
    n = res_nquery(&res_status, host, C_IN, T_MX, (unsigned char *) answer, sizeof(querybuf));
    if (n < 0) {
	switch (res_status.res_h_errno) {
	    case NO_DATA:
		res_nclose(&res_status);
		goto done;
	    default:
		res_nclose(&res_status);
		return -1;
	}
    }
    res_nclose(&res_status);
    if (n > sizeof(querybuf)) n = sizeof(querybuf);
    hp = (HEADER *) answer;
    cp = (unsigned char *) answer + HFIXEDSZ;
    eom = (unsigned char *) answer + n;
    for (qdcount = ntohs((unsigned short) hp->qdcount); qdcount--; cp += n + QFIXEDSZ) {
	if ((n = dn_skipname(cp, eom)) < 0) goto done;
    }
    buflen = MXBUFFER - 1;
    bp = MXHostBuf;
    ancount = ntohs((unsigned short) hp->ancount);
    while (--ancount >= 0 && cp < eom && nmx < MAXMX - 1) {
	if ((n = dn_expand((unsigned char *) answer, eom, cp, (unsigned char *) bp, buflen)) < 0) break;
	cp += n;
	GETSHORT(type, cp);
	cp += INT16SZ;
	GETLONG(ttl, cp);
	GETSHORT(n, cp);
	if (type != T_MX) {
	    cp += n;
	    continue;
	}
	GETSHORT(pref, cp);
	if ((n = dn_expand((unsigned char *) answer, eom, cp, (unsigned char *) bp, buflen)) < 0) break;
	cp += n;
	n = strlen(bp);
	if (n == 0) continue;
	weight[nmx] = hash_code(bp) & 0xff;
	prefs[nmx] = pref;
	mxhosts[nmx++] = bp;
	bp += n;
	if (bp[-1] != '.') {
	    *bp++ = '.';
	    n++;
	}
	*bp++ = '\0';
	if (buflen < n + 1) break;
	buflen -= n + 1;
    }
    for (i = 0; i < nmx; i++)
	for (j = i + 1; j < nmx; j++)
	    if (prefs[i] > prefs[j] || (prefs[i] == prefs[j] && weight[i] > weight[j])) {
		int temp;
		char *temp1;

		temp = prefs[i];
		prefs[i] = prefs[j];
		prefs[j] = temp;
		temp1 = mxhosts[i];
		mxhosts[i] = mxhosts[j];
		mxhosts[j] = temp1;
		temp = weight[i];
		weight[i] = weight[j];
		weight[j] = temp;
	    }
    if (nmx == 0) {
done:
	strscpy(MXHostBuf, host, MXBUFFER - 1);
	mxhosts[nmx++] = MXHostBuf;
    }
    return nmx;
}

static int check_sender(const char *sender) {
    querybuf *answer;
    char *MXHostBuf, *mxhosts[MAXMX + 1];
    int mxcount, i, rc;

    if (!(MXHostBuf = calloc(1, MXBUFFER))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return -1;
    }
    if (!(answer = calloc(1, sizeof(querybuf)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	free(MXHostBuf);
	return -1;
    }
    if ((mxcount = get_mx_rr(strchr(sender, '@') + 1, MXHostBuf, mxhosts, answer)) <= 0) {
	free(MXHostBuf);
	free(answer);
	return -1;
    }
    free(answer);
    for (i = 0, rc = 0; i < mxcount; i++) {
	rc = mailer(sender, mxhosts[i]);
	if (rc >= 0) break;
    }
    free(MXHostBuf);
    return rc;
}

static int check_recipient(const char *recipient, const char *host) {
    char *p = NULL;

    if ((p = strchr(host, '['))) {
	char wildcardmxhost[MAXLINE];

	strscpy(wildcardmxhost, p + 1, sizeof(wildcardmxhost) - 1);
	if ((p = strrchr(wildcardmxhost, ']'))) *p = '\0';
	return mailer(recipient, wildcardmxhost);
    }
    return mailer(recipient, host);
}

static int check_recipient_by_mx(const char *recipient, const char *domain) {
    querybuf *answer;
    char *MXHostBuf, *mxhosts[MAXMX + 1];
    int mxcount, i, rc;

    if (!(MXHostBuf = calloc(1, MXBUFFER))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return -1;
    }
    if (!(answer = calloc(1, sizeof(querybuf)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	free(MXHostBuf);
	return -1;
    }
    if ((mxcount = get_mx_rr(domain, MXHostBuf, mxhosts, answer)) <= 0) {
	free(MXHostBuf);
	free(answer);
	return -1;
    }
    free(answer);
    for (i = 0, rc = 0; i < mxcount; i++) {
	rc = mailer(recipient, mxhosts[i]);
	if (rc >= 0) break;
    }
    free(MXHostBuf);
    return rc;
}

static sfsistat smf_connect(SMFICTX *ctx, char *name, _SOCK_ADDR *sa) {
    struct context *context = NULL;
    char host[64];

    strscpy(host, "undefined", sizeof(host) - 1);
    switch (sa->sa_family) {
	case AF_INET: {
	    struct sockaddr_in *sin = (struct sockaddr_in *)sa;

	    inet_ntop(AF_INET, &sin->sin_addr.s_addr, host, sizeof(host));
	    break;
	}
	case AF_INET6: {
	    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

	    inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
	    break;
	}
    }
    if (!(context = calloc(1, sizeof(*context)))) {
	syslog(LOG_ERR, "[ERROR] %s", strerror(errno));
	return SMFIS_ACCEPT;
    }
    smfi_setpriv(ctx, context);
    strscpy(context->addr, host, sizeof(context->addr) - 1);
    strscpy(context->fqdn, name, sizeof(context->fqdn) - 1);
    
    if (strncmp((char *)(context->fqdn+1),context->addr,strlen(context->addr))==0)
       context->fqdn[0]=0;  
    
    return SMFIS_CONTINUE;
}

static sfsistat smf_envfrom(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *interface = smfi_getsymval(ctx, "{if_addr}");
    const char *verify = smfi_getsymval(ctx, "{verify}");

    if (interface && strcmp(interface, context->addr) == 0) return SMFIS_ACCEPT;
    if (smfi_getsymval(ctx, "{auth_authen}")) return SMFIS_ACCEPT;
    if (verify && strcmp(verify, "OK") == 0) return SMFIS_ACCEPT;

    if (*args) strscpy(context->from, *args, sizeof(context->from) - 1);
    if (!strstr(context->from, "<>") && !address_preparation(context->sender, context->from)) {
	smfi_setreply(ctx, "550", "5.1.7", "Sender address does not conform to RFC-2821 syntax");
	return SMFIS_REJECT;
    }

    context->slowdown = 0;

    return SMFIS_CONTINUE;
}



static sfsistat smf_eoh(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *queueid = smfi_getsymval(ctx, "i");

    if (conf.cidrs && ip_check(inet_addr(context->addr))) return SMFIS_ACCEPT;
    if (conf.ptrs && ptr_check(context->fqdn)) return SMFIS_ACCEPT;

    if (!strstr(context->from, "<>")) {
        strtolower(context->from);
	if (conf.froms && from_check(context->sender)) return SMFIS_ACCEPT;
    }

    if (!strstr(context->from, "<>") && conf.sav) {
	char human_time[10];
	time_t tstart, tend;
	int ret = 1;

	if (cache) {
	    cache_item_status status;

	    mutex_lock(&cache_mutex);
	    status = cache_get(context->sender, SENDERS);
	    mutex_unlock(&cache_mutex);
	    switch (status) {
		case SENDER_PASS:
		    syslog(LOG_INFO, "sender check succeeded (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		     
		    return SMFIS_CONTINUE;
		case SENDER_FAIL:
		    syslog(LOG_INFO, "sender check failed (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		    do_sleep(1);
		    smfi_setreply(ctx, "550", "5.1.8", "Sender address verification failed, check your MX");
		    return SMFIS_REJECT;
		case SENDER_TEMPFAIL:
		    syslog(LOG_INFO, "sender check tempfailed (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		    do_sleep(1);
		    smfi_setreply(ctx, "451", "4.1.8", "Temporary failure in sender address verification");
		    return SMFIS_TEMPFAIL;
		default:
		    break;
	    }
	}
	time(&tstart);
	ret = check_sender(context->sender);
	time(&tend);
	time_humanize(human_time, tend - tstart);
	if (ret == 0) {
	    if (cache && conf.from_fail_ttl) {
		mutex_lock(&cache_mutex);
		cache_put(context->sender, conf.from_fail_ttl, SENDERS, SENDER_FAIL, CACHE_KEEP);
		mutex_unlock(&cache_mutex);
	    }
	    syslog(LOG_NOTICE, "sender check failed: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
  	    do_sleep(1);
	    smfi_setreply(ctx, "550", "5.1.8", "Sender address verification failed, check your MX");
	    return SMFIS_REJECT;
	}
	if (ret < 0 && !conf.ignore_tempfail) {
	    if (cache && conf.from_tempfail_ttl) {
		mutex_lock(&cache_mutex);
		cache_put(context->sender, conf.from_tempfail_ttl, SENDERS, SENDER_TEMPFAIL, CACHE_KEEP);
		mutex_unlock(&cache_mutex);
	    }
	    syslog(LOG_NOTICE, "sender check tempfailed: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
  	    do_sleep(1);
	    smfi_setreply(ctx, "451", "4.1.8", "Temporary failure in sender address verification");
	    return SMFIS_TEMPFAIL;
	}
	if (ret > 0) {
	    if (cache && conf.from_pass_ttl) {
		mutex_lock(&cache_mutex);
		cache_put(context->sender, conf.from_pass_ttl, SENDERS, SENDER_PASS, CACHE_KEEP);
		mutex_unlock(&cache_mutex);
	    }
	    syslog(LOG_INFO, "sender check succeeded: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
	    return SMFIS_ACCEPT;
	}
    }
    return SMFIS_CONTINUE;
}



static sfsistat smf_envrcpt(SMFICTX *ctx, char **args) {
    struct context *context = (struct context *)smfi_getpriv(ctx);
    const char *rcpt_mailer = smfi_getsymval(ctx, "{rcpt_mailer}");
    const char *rcpt_host = smfi_getsymval(ctx, "{rcpt_host}");
    const char *rcpt_addr = smfi_getsymval(ctx, "{rcpt_addr}");
    const char *queueid = smfi_getsymval(ctx, "i");
    char human_time[10];
    time_t tstart, tend;
    int ret = 1;

    if (*args) strscpy(context->rcpt, *args, sizeof(context->rcpt) - 1);
    if (!address_preparation(context->recipient, context->rcpt)) {
	smfi_setreply(ctx, "550", "5.1.3", "Recipient address does not conform to RFC-2821 syntax");
	return SMFIS_REJECT;
    }
    strtolower(context->recipient);
    if (!conf.mail_store) goto penalty;
    if (context->slowdown) do_sleep(SLOW_DOWN_SLICE * context->slowdown);
    if (cache) {
	cache_item_status status;

	mutex_lock(&cache_mutex);
	status = cache_get(context->recipient, RECIPIENTS);
	mutex_unlock(&cache_mutex);
	switch (status) {
	    case RECIPIENT_PASS:
		syslog(LOG_INFO, "recipient check succeeded (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		goto penalty;
	    case RECIPIENT_FAIL:
		context->slowdown++;
		do_sleep(1);
		syslog(LOG_INFO, "recipient check failed (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		smfi_setreply(ctx, "550", "5.1.1", "Sorry, no mailbox here by that name or mailbox is over quota");
		return SMFIS_REJECT;
	    case RECIPIENT_TEMPFAIL:
		do_sleep(1);
		syslog(LOG_INFO, "recipient check tempfailed (cached): from=%s, to=%s, %s [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr,queueid);
		smfi_setreply(ctx, "451", "4.2.1", "Mailbox is not available now, try again later");
		return SMFIS_TEMPFAIL;
	    default:
		break;
	}
    }
    time(&tstart);
    if (rcpt_mailer && !strcasecmp(rcpt_mailer, "local")) {
	    // Don't check local adresses
	    goto penalty;
    }
    else
	if (rcpt_mailer && rcpt_host && rcpt_addr)
	    if (!strcasecmp(rcpt_mailer, "smtp") || !strcasecmp(rcpt_mailer, "esmtp")) {
		if (strchr(rcpt_host, '['))
		    ret = check_recipient(rcpt_addr, rcpt_host);
		else
		    ret = check_recipient_by_mx(rcpt_addr, rcpt_host);
	    }
    time(&tend);
    time_humanize(human_time, tend - tstart);
    if (ret == 0) {
	context->slowdown++;
	if (cache && conf.to_fail_ttl) {
	    mutex_lock(&cache_mutex);
	    cache_put(context->recipient, conf.to_fail_ttl, RECIPIENTS, RECIPIENT_FAIL, CACHE_KEEP);
	    mutex_unlock(&cache_mutex);
	}
	do_sleep(1);
	syslog(LOG_NOTICE, "recipient check failed: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
	smfi_setreply(ctx, "550", "5.1.1", "Sorry, no mailbox here by that name or mailbox is over quota");
	return SMFIS_REJECT;
    }
    if (ret < 0) {
	if (cache && conf.to_tempfail_ttl) {
	    mutex_lock(&cache_mutex);
	    cache_put(context->recipient, conf.to_tempfail_ttl, RECIPIENTS, RECIPIENT_TEMPFAIL, CACHE_KEEP);
	    mutex_unlock(&cache_mutex);
	}
	do_sleep(1);
	syslog(LOG_NOTICE, "recipient check tempfailed: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
	smfi_setreply(ctx, "451", "4.2.1", "Mailbox is not available now, try again later");
	return SMFIS_TEMPFAIL;
    }
    if (cache && conf.to_pass_ttl) {
	mutex_lock(&cache_mutex);
	cache_put(context->recipient, conf.to_pass_ttl, RECIPIENTS, RECIPIENT_PASS, CACHE_KEEP);
	mutex_unlock(&cache_mutex);
    }
    syslog(LOG_INFO, "recipient check succeeded: from=%s, to=%s, %s [%s], [%s], id=%s", context->from, context->rcpt, context->fqdn, context->addr, human_time,queueid);
penalty:    
    if (to_check(context->recipient)) return SMFIS_ACCEPT;
    
    return SMFIS_CONTINUE;
}

static sfsistat smf_close(SMFICTX *ctx) {
    struct context *context = (struct context *)smfi_getpriv(ctx);

    if (context) {
	free(context);
	smfi_setpriv(ctx, NULL);
    }
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter = {
    "smf-sav",
    SMFI_VERSION,  // if not able so start, change this to 2
    0,
    smf_connect,
    NULL,
    smf_envfrom,
    smf_envrcpt,
    NULL,
    smf_eoh,
    NULL,
    NULL,
    NULL,
    smf_close
};

int main(int argc, char **argv) {
    const char *ofile = NULL;
    int ch, ret = 0;

    while ((ch = getopt(argc, argv, "hc:")) != -1) {
	switch (ch) {
	    case 'h':
		fprintf(stderr, "Usage: smf-sav -c <config file>\n");
		return 0;
	    case 'c':
		if (optarg) config_file = optarg;
		break;
	    default:
		break;
	}
    }
    memset(&conf, 0, sizeof(conf));
    regcomp(&re_ipv4, IPV4_DOT_DECIMAL, REG_EXTENDED|REG_ICASE);
    if (!load_config()) fprintf(stderr, "Warning: smf-sav configuration file load failed\n");
    tzset();
    openlog("smf-sav", LOG_PID|LOG_NDELAY, conf.syslog_facility);
    if (!strncmp(conf.sendmail_socket, "unix:", 5))
	ofile = conf.sendmail_socket + 5;
    else
	if (!strncmp(conf.sendmail_socket, "local:", 6)) ofile = conf.sendmail_socket + 6;
    if (ofile) unlink(ofile);
    if (!getuid()) {
	struct passwd *pw;

	if ((pw = getpwnam(conf.run_as_user)) == NULL) {
	    fprintf(stderr, "%s: %s\n", conf.run_as_user, strerror(errno));
	    goto done;
	}
	setgroups(1, &pw->pw_gid);
	if (setgid(pw->pw_gid)) {
	    fprintf(stderr, "setgid: %s\n", strerror(errno));
	    goto done;
	}
	if (setuid(pw->pw_uid)) {
	    fprintf(stderr, "setuid: %s\n", strerror(errno));
	    goto done;
	}
    }
    if (smfi_setconn((char *)conf.sendmail_socket) != MI_SUCCESS) {
	fprintf(stderr, "smfi_setconn failed: %s\n", conf.sendmail_socket);
	goto done;
    }
    if (smfi_register(smfilter) != MI_SUCCESS) {
	fprintf(stderr, "smfi_register failed\n");
	goto done;
    }
    if (daemon(0, 0)) {
	fprintf(stderr, "daemonize failed: %s\n", strerror(errno));
	goto done;
    }
    if (pthread_mutex_init(&cache_mutex, 0)) {
	fprintf(stderr, "pthread_mutex_init failed\n");
	goto done;
    }
    umask(0177);
    signal(SIGPIPE, SIG_IGN);
    if (!cache_init()) syslog(LOG_ERR, "[ERROR] cache engine init failed");
    ret = smfi_main();
    if (ret != MI_SUCCESS) syslog(LOG_ERR, "[ERROR] terminated due to a fatal error");
    if (cache) cache_destroy();
    pthread_mutex_destroy(&cache_mutex);
done:
    free_config();
    closelog();
    return ret;
}

