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
	char *p = NULL;

	if ((p = strstr(lineproc->cad, "Priority:"))) {
		memcpy(lineproc->prio, p, 12);

		if (isdigit(lineproc->prio[10]))
			if (priority >= (lineproc->prio[10] - 48)) return(1);
	}

	return(0);
}

int
s2c_parse_ip(lineproc_t *lineproc)
{
	unsigned int i = 0, len = 0;

	memset((regmatch_t*)lineproc->resultado, 0x00, (REGARSIZ * sizeof(regmatch_t)));

	if (regexec(&lineproc->expr, lineproc->cad, REGARSIZ, lineproc->resultado, 0) == 0) {
		for (i = 0; i < REGARSIZ; i++){
			len = lineproc->resultado[i + 1].rm_eo - lineproc->resultado[i + 1].rm_so;

			if(len){
				memcpy(lineproc->ret[i], lineproc->cad + lineproc->resultado[i + 1].rm_so, len);
				lineproc->ret[i][len]='\0';
			} else {
				strlcpy(lineproc->lastret, lineproc->ret[i - 1], sizeof(lineproc->lastret));
				return(1);
			}
		}
	}
	return(0);
}

void
s2c_parse_and_block(loopdata_t *loopdata, lineproc_t *lineproc, wbhead_t *wbhead)
{
	unsigned pb_status = 0, threadcheck = 0;

	if (!s2c_parse_priority(loopdata->priority, lineproc)) return;
	if (!s2c_parse_ip(lineproc)) return;

	if (!LIST_EMPTY(&wbhead->whead))
		if (s2c_parse_search_wl(lineproc->lastret, &wbhead->whead)) return;

	if ((pb_status = s2c_parse_and_block_bl(lineproc->lastret, &wbhead->bhead)) == loopdata->repeat_offenses) {

		pthread_mutex_lock(&thr_mutex);
		s2c_threads++;
		threadcheck = s2c_threads;
		pthread_mutex_unlock(&thr_mutex);

		if(threadcheck < loopdata->thr_max)
			s2c_spawn_block_log(loopdata->D, lineproc->lastret, loopdata->logfile);

		s2c_pf_block(loopdata->dev, loopdata->tablename, lineproc->lastret);
		if (v) syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_BLK, lineproc->lastret);

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
	
	memset(lineproc, 0x00, sizeof(lineproc_t));

	if ((file = fopen(wfile, "r")) == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, wfile, LANG_WARN);
		return;
	}

	flockfile(file);

	while (s2c_parse_line(lineproc->cad, file)) {
		if (s2c_parse_ip(lineproc)) {

			if ((ipw2 = (struct ipwlist *)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			memset(ipw2, 0x00, sizeof(struct ipwlist));
			ipw2->waddr = *cidr_from_str(lineproc->lastret);

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

	if ((blfile = fopen(bfile, "r")) == NULL) {
		syslog(LOG_ERR | LOG_DAEMON, "%s %s - %s", LANG_NO_OPEN, bfile, LANG_WARN);
		return;
	}

	flockfile(blfile);
	memset(lineproc, 0x00, sizeof(lineproc_t));
	strlcat(tablename, "_static", PF_TABLE_NAME_SIZE);
	s2c_pf_ruleadd(dev, tablename);

	while (s2c_parse_line(lineproc->cad, blfile))
		if (s2c_parse_ip(lineproc)) {

			if (!LIST_EMPTY(whead))
				if (s2c_parse_search_wl(lineproc->lastret, whead))
					syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", LANG_BENT, lineproc->lastret, LANG_WL, LANG_WARN);

			s2c_pf_block(dev, tablename, lineproc->lastret);
		}

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

int
s2c_parse_search_wl(char *ip, struct wlist_head *wl)
{
	struct ipwlist *aux2 = NULL;
	CIDR *ipcidr = cidr_alloc();
	int f = 0;

	if (ipcidr == NULL) s2c_malloc_err();
	ipcidr = cidr_from_str(ip);

	for (aux2 = wl->lh_first; aux2 != NULL; aux2 = aux2->elem.le_next)
		if (!cidr_contains(&aux2->waddr, ipcidr)) { 
			f = 1; break;
		}

	cidr_free(ipcidr);

	return(f);
}
