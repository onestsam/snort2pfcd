/*
 * snort2pfcd
 * Copyright (c) 2017 Samee Shahzada <onestsam@gmail.com>
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


#include <regex.h>
#include <sys/queue.h> 
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <syslog.h>
#include <libcidr.h>
#include <ifaddrs.h>
#include <pthread.h>

#include "defdata.h"
#include "tools.h"
#include "spfc.h"
#include "parser.h"


int
s2c_parse_and_block_bl(char *ret, struct blist_head *blist)
{
	struct ipblist *aux2 = NULL, *ipb = NULL;

	if (blist->lh_first == NULL){

		if ((ipb = (struct ipblist*)malloc(sizeof(struct ipblist))) == NULL) s2c_malloc_err();
		memset(ipb, 0x00, sizeof(struct ipblist));
		memcpy(ipb->baddr, ret, BUFSIZ);
		ipb->t = time(NULL);
		ipb->repeat_offenses = 0;
		LIST_INIT(blist);
		LIST_INSERT_HEAD(blist, ipb, elem);
		return(0);

	} else {
		for (aux2=blist->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if (!strcmp(aux2->baddr, ret)) {
				aux2->repeat_offenses++;
				return(aux2->repeat_offenses);
			}
			else if (!aux2->elem.le_next) {

				if ((ipb = (struct ipblist*)malloc(sizeof(struct ipblist))) == NULL) s2c_malloc_err();
				memset(ipb, 0x00, sizeof(struct ipblist));
				memcpy(ipb->baddr, ret, BUFSIZ);
				ipb->t = time(NULL);
				ipb->repeat_offenses = 0;
				LIST_INSERT_AFTER(aux2, ipb, elem);
				return(0);
			}
		}
	}

	return(-1);	
}

void
s2c_parse_and_block_bl_clear(struct blist_head *bhead)
{
	struct ipblist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(bhead);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		free(n1);
		n1 = n2;
	}

	return;
}

void
s2c_parse_and_block_wl_clear(struct wlist_head *whead)
{
	struct ipwlist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(whead);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		cidr_free(n1->waddr);
		free(n1);
		n1 = n2;
	}

	return;
}

void
s2c_parse_and_block_bl_del(unsigned long age, unsigned long this_time, struct blist_head *bl)
{
	struct ipblist *aux2 = NULL;

	for (aux2=bl->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next)
		if ((aux2->t + age) < this_time) {
			LIST_REMOVE(aux2, elem);
			free(aux2);
		}

	return;
}

int
s2c_parse_line(char *buf, FILE* wfile)
{
	static char next_ch = ' ';
	int i = 0;

	if (feof(wfile)) return (0);                                

	do {
		next_ch = fgetc(wfile);
		if (i < BUFSIZ) buf[i++] = next_ch;
	} while (!feof(wfile) && !isspace(next_ch));

	if (i >= BUFSIZ) return (-1);

	buf[i] = '\0';
	return(1);
}

int
s2c_parse_priority(int priority, lineproc_t *lineproc)
{
	char *p = NULL;

	p = strstr(lineproc->cad, "Priority:");
	if (p) memcpy(lineproc->prio, p, 12);

	if (isdigit(lineproc->prio[10]))
		if (priority >= (lineproc->prio[10] - 48)) return(1);

	return(0);
}

int
s2c_parse_ip(lineproc_t *lineproc)
{
	int len = 0;
	unsigned int enc = 1;

	if (regcomp(&lineproc->expr, REG_ADDR, REG_EXTENDED) !=0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_ERR_REGEX, LANG_EXIT);
		s2c_exit_fail();
	}

	if (regexec(&lineproc->expr, lineproc->cad, 1, &lineproc->resultado, 0) != 0) enc = 0;
	
	if (enc != 0) {
		len = lineproc->resultado.rm_eo - lineproc->resultado.rm_so;
		memcpy(lineproc->ret, lineproc->cad + lineproc->resultado.rm_so, len);
		lineproc->ret[len]='\0';
	}

	if (enc) return(1);
	else return(0);
}

void
s2c_parse_and_block(int dev, int priority, int repeat_offenses, char *logfile, char *tablename, lineproc_t *lineproc, struct wlist_head *whead, struct blist_head *bhead)
{
	int pb_status = 0;

	if (!s2c_parse_priority(priority, lineproc)) return;
	if (!s2c_parse_ip(lineproc)) return;

	if (!LIST_EMPTY(whead))
		if (s2c_parse_search_wl(lineproc->ret, whead)) return;

	if ((pb_status = s2c_parse_and_block_bl(lineproc->ret, bhead)) == repeat_offenses) {

		s2c_spawn_block_log(lineproc->ret, logfile);
		s2c_pf_block(dev, tablename, lineproc->ret);
	}

	if(pb_status == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INTDB, LANG_EXIT);
		s2c_exit_fail();
	}

	return;
}

int
s2c_parse_load_wl_file(lineproc_t *lineproc, char *wlist_file, struct ipwlist *ipw1)
{
	struct ipwlist *ipw2 = NULL;
	FILE *wlfile = NULL;

	if ((wlfile = fopen(wlist_file, "r")) == NULL) return(1);

	flockfile(wlfile);
	memset(lineproc, 0x00, sizeof(lineproc_t));

	while (s2c_parse_line(lineproc->cad, wlfile)) {
		if (s2c_parse_ip(lineproc)) {

			if ((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			memset(ipw2, 0x00, sizeof(struct ipwlist));

			if ((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();
			ipw2->waddr = cidr_from_str(lineproc->ret);

			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}
	}

	funlockfile(wlfile);
	fclose(wlfile);

	return(0);
}

void
s2c_parse_load_wl_ifaces(struct ipwlist *ipw1)
{
	struct ipwlist *ipw2 = NULL;
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;

	if (getifaddrs(&ifaddr) == -1) {
		syslog(LOG_DAEMON | LOG_ERR, "%s -%s", LANG_IFADDR_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL)
			continue;

		if ((ifa->ifa_addr)->sa_family == AF_INET) {

			if ((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			memset(ipw2, 0x00, sizeof(struct ipwlist));

			if ((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();
			ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);

			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}

	}

	freeifaddrs(ifaddr);
	return;
}

void
s2c_parse_load_bl_static(int dev, lineproc_t *lineproc, char *tablename, struct wlist_head *whead)
{
	FILE *blfile = NULL;

	if ((blfile = fopen(bfile, "r")) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "%s blacklist file - %s", LANG_NO_OPEN, LANG_WARN);
		return;
	}

	flockfile(blfile);
	memset(lineproc, 0x00, sizeof(lineproc_t));
	strlcat(tablename, "_static", PF_TABLE_NAME_SIZE);
	s2c_pf_ruleadd(dev, tablename);

	while (s2c_parse_line(lineproc->cad, blfile))
		if (s2c_parse_ip(lineproc)) {

			if (!LIST_EMPTY(whead))
				if (s2c_parse_search_wl(lineproc->ret, whead))
					syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", LANG_BENT, lineproc->ret, LANG_WL, LANG_WARN);

		s2c_pf_block(dev, tablename, lineproc->ret);
		}

	funlockfile(blfile);
	fclose(blfile);

	bzero(tablename, PF_TABLE_NAME_SIZE);
	strlcpy(tablename, __progname, PF_TABLE_NAME_SIZE);

	return;
}

void
s2c_parse_load_wl(lineproc_t *lineproc, struct wlist_head *head)
{
	struct ipwlist *ipw1 = NULL, *ipw2 = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0;

	if ((ipw1 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
	memset(ipw1, 0x00, sizeof(struct ipwlist));

	if ((ipw1->waddr = cidr_alloc()) == NULL) s2c_malloc_err();
	ipw1->waddr = cidr_from_str("127.0.0.0/8");

	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipw1, elem);

	if (!strcmp(extif, "all")) s2c_parse_load_wl_ifaces(ipw1);
	else {

		if ((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) s2c_malloc_err();
		
		memset(ifr, 0x00, sizeof(struct ifreq));
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, extif, IFNAMSIZ);

		if (ioctl(fd, SIOCGIFADDR, ifr) != 0){
			syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, extif, LANG_EXIT);
			s2c_exit_fail();
		}

		close(fd);
		free(ifr);

		if ((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
		memset(ipw2, 0x00, sizeof(struct ipwlist));

		if ((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();
		ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr);

		LIST_INSERT_AFTER(ipw1, ipw2, elem);
		ipw1 = ipw2;
	}

	if (s2c_parse_load_wl_file(lineproc, PATH_RESOLV, ipw1)) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, PATH_RESOLV, LANG_WARN);
		return;
	}

	if (s2c_parse_load_wl_file(lineproc, wfile, ipw1)) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, wfile, LANG_WARN);
		return;
	}

	return;
}

int
s2c_parse_search_wl(char *ip, struct wlist_head *wl)
{
	struct ipwlist *aux2 = NULL;
	CIDR *ipcidr = cidr_alloc();

	if (ipcidr == NULL) s2c_malloc_err();

	ipcidr = cidr_from_str(ip);
	for (aux2=wl->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
		if (!cidr_contains(aux2->waddr, ipcidr)){
			cidr_free(ipcidr);
			return(1);
		}
	}

	cidr_free(ipcidr);
	return(0);
}
