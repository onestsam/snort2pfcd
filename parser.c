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
s2c_parse_and_block_bl(char *ret, struct ulist_head *head)
{
	struct ipulist *aux2 = NULL, *ipu = NULL;

	if (head->lh_first == NULL){
		if ((ipu = (struct ipulist*)malloc(sizeof(struct ipulist))) == NULL) s2c_malloc_err();

		s2c_parse_ipu_set(ret, ipu);
		LIST_INIT(head);
		LIST_INSERT_HEAD(head, ipu, elem);
		return(0);

	} else {
		for (aux2=head->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if (!strcmp(aux2->chaddr, ret)) {
				aux2->repeat_offenses++;
				return(aux2->repeat_offenses);
			}
			else if (!aux2->elem.le_next) {
				if ((ipu = (struct ipulist*)malloc(sizeof(struct ipulist))) == NULL) s2c_malloc_err();
				s2c_parse_ipu_set(ret, ipu);
				LIST_INSERT_AFTER(aux2, ipu, elem);
				return(0);
			}
		}
	}

	return(-1);	
}

void
s2c_parse_and_block_list_clear(struct ulist_head *head)
{
	struct ipulist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(head);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		free(n1);
		n1 = n2;
	}

	return;
}

void
s2c_parse_and_block_list_timeout(unsigned long age, unsigned long this_time, struct ulist_head *head)
{
	struct ipulist *aux2 = NULL;

	for (aux2=head->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next)
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

	if ((p = strstr(lineproc->cad, "y: "))) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %c", LANG_PRIO, p[3]);
			else fprintf(stderr, "%s - %c", LANG_PRIO, p[3]);
		}
		if (isdigit(p[3]))
			if ((p[3] - 48) >= priority)
				return(1);
	}

	return(0);
}

int
s2c_parse_pattern(char *pattern, lineproc_t *lineproc)
{
	int len = 0;
	char *p = NULL;
	regmatch_t rado[REGARSIZ];

	if ((p = strstr(lineproc->cad, pattern))) {

		memset((regmatch_t*)rado, 0x00, (REGARSIZ * sizeof(regmatch_t)));

		if(regexec(&lineproc->expr, lineproc->cad, REGARSIZ, rado, 0) == 0) {
			len = (rado[0].rm_eo - rado[0].rm_so);

			if(len) {
				memset((char *)lineproc->ret, 0x00, (BUFSIZ * sizeof(char)));
				memcpy(lineproc->ret, (lineproc->cad + rado[0].rm_so), len);
				lineproc->ret[len]='\0';
				return(1);
			}
		}
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

	return(i);
}

void
s2c_parse_and_block(loopdata_t *loopdata, lineproc_t *lineproc)
{
	int pb_status = 0, threadcheck = 0;

	if (!s2c_parse_priority(loopdata->priority, lineproc)) return;
	if (!s2c_parse_ip(lineproc)) {
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s", LANG_NO_REG);
			else fprintf(stderr, "%s", LANG_NO_REG);
		}
		return;
	}

	if (!LIST_EMPTY(&loopdata->wbhead.whead)) {
		if (s2c_parse_search_list(lineproc->ret, &loopdata->wbhead.whead))
			return;
	}

	if ((pb_status = s2c_parse_and_block_bl(lineproc->ret, &loopdata->wbhead.bhead)) == loopdata->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2c_threads++;
		threadcheck = s2c_threads;
		pthread_mutex_unlock(&thr_mutex);

		if(threadcheck < loopdata->thr_max)
			s2c_spawn_block_log(loopdata->D, lineproc->ret, loopdata->logfile);

		s2c_pf_block(loopdata->dev, loopdata->tablename, lineproc->ret);
		if (v) {
			if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_BLK, lineproc->ret);
			else fprintf(stderr, "%s - %s", LANG_BLK, lineproc->ret);
		}

	} else if (pb_status == -1) {
		if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_INTDB, LANG_EXIT);
		else fprintf(stderr, "%s - %s", LANG_INTDB, LANG_EXIT);
		s2c_exit_fail();
	}

	return;
}

void
s2c_parse_load_file(loopdata_t *loopdata, lineproc_t *lineproc, char *ufile, struct ulist_head *head, struct ipulist *ipu1, int id)
{
	struct ipulist *ipu2 = NULL;
	FILE *file = NULL;

	if ((file = fopen(ufile, "r")) == NULL) {
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, ufile, LANG_WARN);
		else fprintf(stderr, "%s %s - %s", LANG_NO_OPEN, ufile, LANG_WARN);
		return;
	}

	flockfile(file);

	while (s2c_parse_line(lineproc->cad, file)) {
		if (s2c_parse_ip(lineproc)) {

			if(id == ID_WF) {
				if ((ipu2 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2c_malloc_err();
				s2c_parse_ipu_set(lineproc->ret, ipu2);
				LIST_INSERT_AFTER(ipu1, ipu2, elem);
				ipu1 = ipu2;
			}

			if (id == ID_BF) {
				if (!LIST_EMPTY(head))
					if (s2c_parse_search_list(lineproc->ret, head)) {
						if (!F) syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", LANG_BENT, lineproc->ret, LANG_WL, LANG_WARN);
						else fprintf(stderr, "%s %s %s - %s", LANG_BENT, lineproc->ret, LANG_WL, LANG_WARN);
					}

				s2c_pf_ruleadd(loopdata->dev, loopdata->tablename_static);
				s2c_pf_block(loopdata->dev, loopdata->tablename_static, lineproc->ret);
			}
		}
	}

	funlockfile(file);
	fclose(file);

	return;
}

void
s2c_parse_load_ifaces(struct ipulist *ipu1)
{
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;

	if (getifaddrs(&ifaddr) == -1) {
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s -%s", LANG_IFADDR_ERROR, LANG_EXIT);
		else fprintf(stderr, "%s -%s", LANG_IFADDR_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) continue;
		if ((ifa->ifa_addr)->sa_family == AF_INET)
			s2c_parse_add_list(ipu1, ifa);
	}

	freeifaddrs(ifaddr);

	return;
}

void
s2c_parse_add_list(struct ipulist *ipu1, struct ifaddrs *ifa)
{
	struct ipulist *ipu2 = NULL;
	char ret[BUFSIZ];

	if ((ipu2 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2c_malloc_err();

	inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ret, INET_ADDRSTRLEN);
	s2c_parse_ipu_set(ret, ipu2);

	LIST_INSERT_AFTER(ipu1, ipu2, elem);
	ipu1 = ipu2;

	return;
}

void
s2c_parse_load_wl(loopdata_t *loopdata, char *wfile, lineproc_t *lineproc, struct ulist_head *head)
{
	struct ipulist *ipu1 = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0;

	if ((ipu1 = (struct ipulist *)malloc(sizeof(struct ipulist))) == NULL) s2c_malloc_err();
	memset(ipu1, 0x00, sizeof(struct ipulist));

	ipu1->ciaddr = *cidr_from_str("127.0.0.0/8");
	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipu1, elem);

	if (!strcmp(loopdata->extif, "all")) s2c_parse_load_ifaces(ipu1);
	else {

		if ((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) s2c_malloc_err();
		memset(ifr, 0x00, sizeof(struct ifreq));
		
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, loopdata->extif, IFNAMSIZ);

		pthread_mutex_lock(&pf_mutex);
		if (ioctl(fd, SIOCGIFADDR, ifr) != 0){
			if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, loopdata->extif, LANG_EXIT);
			else fprintf(stderr, "%s %s - %s", LANG_NO_OPEN, loopdata->extif, LANG_EXIT);
			s2c_exit_fail();
		}
		pthread_mutex_unlock(&pf_mutex);

		close(fd);
		free(ifr);

	s2c_parse_add_list(ipu1, (struct ifaddrs *)&(ifr->ifr_addr));
	}

	if (!loopdata->Z) s2c_parse_load_file(loopdata, lineproc, PATH_RESOLV, head, ipu1, ID_WF);
	s2c_parse_load_file(loopdata, lineproc, wfile, head, ipu1, ID_WF);

	return;
}

void
s2c_parse_print_list(struct ulist_head *head)
{
	struct ipulist *aux2 = NULL;

	if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s", LANG_WLL);
	else fprintf(stderr, "%s", LANG_WLL);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!F) syslog(LOG_DAEMON | LOG_ERR, "%s", aux2->chaddr);
		else fprintf(stderr, "%s", aux2->chaddr);

	return;
}

int
s2c_parse_search_list(char *ip, struct ulist_head *head)
{
	struct ipulist *aux2 = NULL;
	CIDR ipcidr;
	int f = 0;

	ipcidr = *cidr_from_str(ip);

	for (aux2 = head->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!cidr_contains(&aux2->ciaddr, &ipcidr)) { 
			f = 1; break;
		}

	return(f);
}

void
s2c_parse_ipu_set(char *ret, struct ipulist *ipu)
{
	memset(ipu, 0x00, sizeof(struct ipulist));
	strlcpy(ipu->chaddr, ret, BUFSIZ);
	ipu->ciaddr = *cidr_from_str(ret);
	if (!C) ipu->t = time(NULL);
	else ipu->t = 0;
	ipu->repeat_offenses = 0;

	return;
}
