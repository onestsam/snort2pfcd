/*
 * snort2pfcd
 * Copyright (c) 2020 Samee Shahzada <onestsam@gmail.com>
 *
 * Based on snort2c
 * Copyright (c) 2005 Antonio Benojar <zz.stalker@gmail.com>
 * Copyright (c) 2002 Cedric Berger
 *
 * Expiretable functions from expiretable
 * Copyright (c) 2005 Henrik Gustafsson <henrik.gustafsson@fnord.se>
 *
 * s2c_parse_line based in pfctl code (pfctl_radix.c)
 * Copyright (c) Armin's Wolfermann
 *
 * s2c_pf_block functions are based
 * on Armin's Wolfermann pftabled-1.03 functions.
 *
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _DEFDATA_H_
#define _DEFDATA_H_

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/event.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <arpa/inet.h>
#include <libcidr.h>
#include <regex.h>
#include <libutil.h>
#include <netdb.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <syslog.h>
#include <ifaddrs.h>

/* Params */
#define THRMAX		100
#define NMBUFSIZ	128
#define REGARSIZ	10
#define EXPTIME		60*60
#define ID_WF		0
#define ID_BF		1
#define ID_AF		2
#define PFDEVICE "/dev/pf"
#define REG_ADDR "(((2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)\\.){3}(2(5[0-5]|[0-4][0-9])|[01]?[0-9][0-9]?)(/(3[012]|[12]?[0-9]))?)"
/* REG_ADDR from https://stackoverflow.com/questions/53497/regular-expression-that-matches-valid-ipv6-addresses */

/* Paths */
#define PATH_LOG "/var/log/"
#define PATH_RUN "/var/run/"
#define PATH_RESOLV "/etc/resolv.conf"
#define PATH_ALERT "/var/log/snort/alert"
#define PATH_WHITELIST "/usr/local/etc/snort/rules/iplists/default.whitelist"
#define PATH_BLACKLIST "/usr/local/etc/snort/rules/iplists/default.blacklist"

/* Language */
#define LANG_EXIT "exiting"
#define LANG_WARN "warning"
#define LANG_RELOAD "reloading"
#define LANG_START "started"
#define LANG_USE "usage"
#define LANG_MAN "see man"
#define LANG_ARG "argument for"
#define LANG_NUM "must be a number"
#define LANG_PF "packet filter"
#define LANG_BLK "Blocked "
#define LANG_BENT "blacklist entry"
#define LANG_WL "is whitelisted"
#define LANG_DETAILS "for more details"
#define LANG_NO_DAEMON "cannot daemonize"
#define LANG_MALLOC_ERROR "malloc error"
#define LANG_STATE_CHANGE "state change detected in"
#define LANG_INTDB "!! internal database error !!"
#define LANG_CON_EST "connection with pf established"
#define LANG_IOCTL_WAIT "attempting to re-establish connection with pf"
#define LANG_IOCTL_ERROR "unable to connect to pf"
#define LANG_IFADDR_ERROR "ifaddr error"
#define LANG_MUTEX_ERROR "unable to init mutex"
#define LANG_NO_OPEN "unable to open"
#define LANG_RECEXIT "exit signal received - exiting"
#define LANG_DAEMON_RUNNING "daemon already running"
#define LANG_NO_PID "cannot open or create pidfile"
#define LANG_INIT_THR "unable to init detached thread attributes"
#define LANG_SET_THR "unable to set detached thread attributes"
#define LANG_LAUNCH_THR "unable to launch detached thread attributes"
#define LANG_NOT_WHITELISTED "not whitelisted, added to block table"
#define LANG_UNBLOCKED "block-time expired, removed from block table"
#define LANG_ERR_ROOT "error: must be root to run"
#define LANG_ERR_REGEX "error compiling regex expr"
#define LANG_KQ_ERROR "kqueue init error"
#define LANG_KE_REQ_ERROR "kevent request error"
#define LANG_KE_READ_ERROR "kevent read error"
#define LANG_KE_ERROR "unable to set kevent structure"
#define LANG_FILE_ERROR "file error: file is a directory"
#define LANG_LOGTHR_ERROR "!! internal log thread error !!"
#define LANG_DNS_DISABLED "DNS lookup disabled"

/* Macros */
LIST_HEAD(wlist_head, ipwlist);
LIST_HEAD(blist_head, ipblist);

/* Global structs */
struct ipwlist {
	CIDR waddr;
	LIST_ENTRY(ipwlist) elem;
};

struct ipblist {
	unsigned long t;
	int repeat_offenses;
	char baddr[BUFSIZ];
	LIST_ENTRY(ipblist) elem;
};

typedef struct _pftbl_t {
	struct pfioc_table io;
	struct pfr_table table;
} pftbl_t;

typedef struct _thread_expt_t {
	int dev;
	unsigned long t;
	char logfile[NMBUFSIZ];
	char nmpfdev[NMBUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
} thread_expt_t;

typedef struct _thread_log_t {
	int D;
	char logip[BUFSIZ];
	char logfile[NMBUFSIZ];
} thread_log_t;

typedef struct _wbhead_t {
	struct wlist_head whead;
	struct blist_head bhead;
} wbhead_t;

typedef struct _lineproc_t {
	regex_t expr;
	regmatch_t resultado[REGARSIZ];
	char prio[BUFSIZ];
	char cad[BUFSIZ];
	char ret[REGARSIZ][BUFSIZ];
	char lastret[BUFSIZ];
} lineproc_t;

typedef struct _pfbl_log_t {
	char message[BUFSIZ];
	char local_logip[BUFSIZ];
	char local_logfile[NMBUFSIZ];
	char hbuf[NI_MAXHOST];
	struct sockaddr sa;
} pfbl_log_t;

typedef struct _loopdata_t {
	int B;
	int W;
	int D;
	int Z;
	int fd;
	int kq;
	int dev;
	unsigned long t;
	int priority;
	int thr_max;
	int repeat_offenses;
	char wfile[NMBUFSIZ];
	char bfile[NMBUFSIZ];
	char extif[IFNAMSIZ];
	char logfile[NMBUFSIZ];
	char nmpfdev[NMBUFSIZ];
	char alertfile[NMBUFSIZ];
	char tablename[PF_TABLE_NAME_SIZE];
} loopdata_t;

typedef struct _thread_fm_t {
	int fid;
        int fileread;
        int *file_monitor;
        loopdata_t loopdata;
} thread_fm_t;

/* Global vars */
extern char *__progname;
int v;
int s2c_threads;
int pf_reset;
int afile_monitor;
int wfile_monitor;
int bfile_monitor;
pthread_mutex_t log_mutex;
pthread_mutex_t dns_mutex;
pthread_mutex_t thr_mutex;
pthread_mutex_t pf_mutex;
pthread_mutex_t fm_mutex;

/* Function defs */
void usage();
void sighandle();
void s2c_daemonize();
void s2c_exit_fail();
void s2c_malloc_err();
void s2c_init(loopdata_t *);
void s2c_thr_init(loopdata_t *);
void s2c_pf_ioctl(int, unsigned long, void *);
void s2c_spawn_file_monitor(int *, int, int, loopdata_t *);
void s2c_spawn_expiretable(loopdata_t *);
void s2c_spawn_block_log(int, char *, char *);
void s2c_spawn_thread(void *(*) (void *), void *);
void s2c_mutex_init();
void s2c_mutex_destroy();
void s2c_log_init(char *);
void s2c_check_file(char *);
void s2c_write_file(char *, char *);
void s2c_pftbl_set(char *, pftbl_t *);
void s2c_ipb_set(char *, struct ipblist *);
long lmin(long ,long);
int optnum(char *, char *);

void s2c_pf_block(int, char *, char *);
void s2c_pf_tbl_ping(int, char *, pftbl_t *);
void s2c_pf_tbladd(int, char *);
void s2c_pf_tbldel(int, char *);
void s2c_pf_ruleadd(int, char *);
void s2c_pf_unblock_log(pfbl_log_t *);
void *s2c_file_monitor(void *);
void *s2c_pf_block_log(void *);
void *s2c_pf_expiretable(void *);

int s2c_parse_priority(int, lineproc_t *);
int s2c_parse_line(char *, FILE *);
void s2c_parse_and_block_bl_clear(struct blist_head *);
void s2c_parse_and_block_wl_clear(struct wlist_head *);
void s2c_parse_and_block_bl_static_clear(int, char *);
void s2c_parse_and_block_bl_del(unsigned long, unsigned long, struct blist_head *);
void s2c_parse_and_block(loopdata_t *, lineproc_t *, wbhead_t *);
void s2c_parse_load_bl_static(int, lineproc_t *, char*, char *, struct wlist_head *);
int s2c_parse_and_block_bl(char *, struct blist_head *);
void s2c_parse_load_wl_file(lineproc_t *, char *, struct ipwlist *);
void s2c_parse_load_wl_ifaces(struct ipwlist *);
void s2c_parse_load_wl(int, char *, char *, lineproc_t *, struct wlist_head *);
int s2c_parse_search_wl(char *, struct wlist_head *);

int s2c_fd_open(char *);
int s2c_kevent_read(loopdata_t *, wbhead_t *, lineproc_t *, int);
void s2c_kevent_open(int *, int *, char *);
void s2c_kevent_blf_load(loopdata_t *, lineproc_t *, wbhead_t *);
void s2c_kevent_wlf_load(loopdata_t *, lineproc_t *, wbhead_t *);
void s2c_kevent_loop(loopdata_t *);
void *s2c_kevent_file_monitor(void *arg);

#endif /* _DEFDATA_H */

