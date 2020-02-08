/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
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
 * libcidr
 * Copyright (c) 1996 Matthew D. Fuller
 *
 * Packet Filter
 * Copyright (c) 2001 Daniel Hartmeier
 * Copyright (c) 2002 - 2008 Henning Brauer
 * Copyright (c) 2012 Gleb Smirnoff <glebius@FreeBSD.org>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *    - Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *    - Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "defdata.h"

int
s2c_parse_and_block_bl(char *ret, struct blist_head *blist)
{
	struct ipblist *aux2 = NULL, *ipb = NULL;

	if (blist->lh_first == NULL){
		if ((ipb = (struct ipblist*)malloc(sizeof(struct ipblist))) == NULL) s2c_malloc_err();

		s2c_ipb_set(ret, ipb);
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
				s2c_ipb_set(ret, ipb);
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
		free(n1);
		n1 = n2;
	}

	return;
}

void
s2c_parse_and_block_bl_static_clear(int dev, char *tablename)
{
	strlcat(tablename, "_static", PF_TABLE_NAME_SIZE);
	s2c_pf_tbldel(dev, tablename);
	memset(tablename, 0x00, PF_TABLE_NAME_SIZE);
	strlcpy(tablename, __progname, PF_TABLE_NAME_SIZE);

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
	char *p = NULL, c;

	if ((p = strstr(lineproc->cad, "Prio"))) {
		c = p[10];

		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %c", LANG_PRIO, c);
		if (isdigit(c))
			if (priority >= (c - 48)) return(1);
	}

	return(0);
}

int
s2c_parse_ip(lineproc_t *lineproc)
{
	int len = 0, i = 0;
	char *regpos = NULL;
	regmatch_t rado[REGARSIZ];

	memset((regmatch_t*)rado, 0x00, (REGARSIZ * sizeof(regmatch_t)));
	regpos = lineproc->cad;

	for (i = 0; (regexec(&lineproc->expr, regpos, REGARSIZ, rado, 0) == 0); i++) {

		len = (rado[0].rm_eo - rado[0].rm_so);

		if(len) {
			memset((char *)lineproc->ret, 0x00, (BUFSIZ * sizeof(char)));
			memcpy(lineproc->ret, (regpos + rado[0].rm_so), len);
			lineproc->ret[len]='\0';
			regpos = (regpos + rado[0].rm_eo);
			memset((regmatch_t*)rado, 0x00, (REGARSIZ * sizeof(regmatch_t)));
		}
	}

	if (i > 1)
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_FOUND, lineproc->ret);

	return(i);
}

void
s2c_parse_and_block(loopdata_t *loopdata, lineproc_t *lineproc, wbhead_t *wbhead)
{
	int pb_status = 0, threadcheck = 0;
	CIDR *ipcidr = NULL;

	if (!s2c_parse_priority(loopdata->priority, lineproc)) return;
	if (!s2c_parse_ip(lineproc)) {
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_NO_REG);
		return;
	}

	if (!LIST_EMPTY(&wbhead->whead)) {
		if ((ipcidr = cidr_alloc()) == NULL) s2c_malloc_err();
		if (s2c_parse_search_wl(lineproc->ret, &wbhead->whead, ipcidr)) {
			cidr_free(ipcidr);
			return;
		}
	cidr_free(ipcidr);
	}

	if ((pb_status = s2c_parse_and_block_bl(lineproc->ret, &wbhead->bhead)) == loopdata->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2c_threads++;
		threadcheck = s2c_threads;
		pthread_mutex_unlock(&thr_mutex);

		if(threadcheck < loopdata->thr_max)
			s2c_spawn_block_log(loopdata->D, lineproc->ret, loopdata->logfile);

		s2c_pf_block(loopdata->dev, loopdata->tablename, lineproc->ret);
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_BLK, lineproc->ret);

	} else if (pb_status == -1) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INTDB, LANG_EXIT);
		s2c_exit_fail();
	}

	return;
}

void
s2c_parse_load_wl_file(lineproc_t *lineproc, char *wfile, struct ipwlist *ipw1)
{
	struct ipwlist *ipw2 = NULL;
	FILE *file = NULL;
	
	if ((file = fopen(wfile, "r")) == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, wfile, LANG_WARN);
		return;
	}

	flockfile(file);

	while (s2c_parse_line(lineproc->cad, file)) {
		if (s2c_parse_ip(lineproc)) {

			if ((ipw2 = (struct ipwlist *)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			memset(ipw2, 0x00, sizeof(struct ipwlist));
			ipw2->waddr = *cidr_from_str(lineproc->ret);

			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}
	}

	funlockfile(file);
	fclose(file);

	return;
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
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_addr)->sa_family == AF_INET) {

			if ((ipw2 = (struct ipwlist *)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			memset(ipw2, 0x00, sizeof(struct ipwlist));

			ipw2->waddr = *cidr_from_inaddr(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}

	}

	freeifaddrs(ifaddr);

	return;
}

void
s2c_parse_load_bl_static(int dev, lineproc_t *lineproc, char *tablename, char *bfile, struct wlist_head *whead)
{
	FILE *blfile = NULL;
	CIDR *ipcidr = NULL;

	if ((blfile = fopen(bfile, "r")) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, bfile, LANG_WARN);
		return;
	}

	flockfile(blfile);
	strlcat(tablename, "_static", PF_TABLE_NAME_SIZE);
	s2c_pf_ruleadd(dev, tablename);

	if ((ipcidr = cidr_alloc()) == NULL) s2c_malloc_err();
	while (s2c_parse_line(lineproc->cad, blfile))
		if (s2c_parse_ip(lineproc)) {

			if (!LIST_EMPTY(whead))
				if (s2c_parse_search_wl(lineproc->ret, whead, ipcidr))
					syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", LANG_BENT, lineproc->ret, LANG_WL, LANG_WARN);

			s2c_pf_block(dev, tablename, lineproc->ret);
		}
	cidr_free(ipcidr);

	funlockfile(blfile);
	fclose(blfile);

	memset(tablename, 0x00, PF_TABLE_NAME_SIZE);
	strlcpy(tablename, __progname, PF_TABLE_NAME_SIZE);

	return;
}

void
s2c_parse_load_wl(int Z, char *extif, char *wfile, lineproc_t *lineproc, struct wlist_head *head)
{
	struct ipwlist *ipw1 = NULL, *ipw2 = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0;

	if ((ipw1 = (struct ipwlist *)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
	memset(ipw1, 0x00, sizeof(struct ipwlist));

	ipw1->waddr = *cidr_from_str("127.0.0.0/8");
	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipw1, elem);

	if (!strcmp(extif, "all")) s2c_parse_load_wl_ifaces(ipw1);
	else {

		if ((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) s2c_malloc_err();
		memset(ifr, 0x00, sizeof(struct ifreq));
		
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, extif, IFNAMSIZ);

		pthread_mutex_lock(&pf_mutex);
		if (ioctl(fd, SIOCGIFADDR, ifr) != 0){
			syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, extif, LANG_EXIT);
			s2c_exit_fail();
		}
		pthread_mutex_unlock(&pf_mutex);

		close(fd);
		free(ifr);

		if ((ipw2 = (struct ipwlist *)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
		memset(ipw2, 0x00, sizeof(struct ipwlist));

		ipw2->waddr = *cidr_from_inaddr(&((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr);
		LIST_INSERT_AFTER(ipw1, ipw2, elem);
		ipw1 = ipw2;
	}

	if (!Z) s2c_parse_load_wl_file(lineproc, PATH_RESOLV, ipw1);
	s2c_parse_load_wl_file(lineproc, wfile, ipw1);

	return;
}

void
s2c_parse_print_wl(struct wlist_head *wl)
{
	struct ipwlist *aux2 = NULL;

	syslog(LOG_DAEMON | LOG_ERR, "%s", LANG_WLL);

	for (aux2 = wl->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		syslog(LOG_DAEMON | LOG_ERR, "%s", cidr_to_str(&aux2->waddr, CIDR_NOFLAGS));

	return;
}

int
s2c_parse_search_wl(char *ip, struct wlist_head *wl, CIDR *ipcidr)
{
	struct ipwlist *aux2 = NULL;
	int f = 0;

	ipcidr = cidr_from_str(ip);

	for (aux2 = wl->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!cidr_contains(&aux2->waddr, ipcidr)) { 
			f = 1; break;
		}

	return(f);
}
