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
s2c_parse_and_block_blisted(char *ret, struct blist_head *blist)
{
	struct ipblist *aux2 = NULL, *ipb = NULL;

	if(blist->lh_first == NULL){

		if((ipb = (struct ipblist*)malloc(sizeof(struct ipblist))) == NULL) s2c_malloc_err();

		memset(ipb, 0x00, sizeof(struct ipblist));
		memcpy(ipb->baddr, ret, BUFMAX);
		ipb->t = time(NULL);

		LIST_INIT(blist);
		LIST_INSERT_HEAD(blist, ipb, elem);
		return(0);

	} else {
		for(aux2=blist->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if(!strcmp(aux2->baddr, ret)) return(1);
			else if(!aux2->elem.le_next) {

				if((ipb = (struct ipblist*)malloc(sizeof(struct ipblist))) == NULL) s2c_malloc_err();

				memset(ipb, 0x00, sizeof(struct ipblist));
				memcpy(ipb->baddr, ret, BUFMAX);
				ipb->t = time(NULL);

				LIST_INSERT_AFTER(aux2, ipb, elem);
				return(0);
			}
		}
	}

	return(0);	
}

void
s2c_parse_and_block_blisted_clear(struct blist_head *bl)
{
	struct ipblist *n1 = NULL, *n2 = NULL;

 	n1 = LIST_FIRST(bl);

	while (n1 != NULL) {
		n2 = LIST_NEXT(n1, elem);
		free(n1);
		n1 = n2;
	}

	LIST_INIT(bl);

	return;
}

void
s2c_parse_and_block_blisted_del(unsigned long t, struct blist_head *bl)
{
	struct ipblist *aux2 = NULL;

	for(aux2=bl->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
		if((aux2->t + EXPTIME) <= t) {
			LIST_REMOVE(aux2, elem);
			free(aux2);
		}
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
		if (i < BUFMAX) buf[i++] = next_ch;
	} while (!feof(wfile) && !isspace(next_ch));

	if (i >= BUFMAX) return (-1);

	buf[i] = '\0';
	return(1);
}

int
s2c_parse_priority(int priority, char *cad)
{
	char *p = NULL, *prio = NULL;

	if((prio = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(prio, BUFMAX);

	p = strstr(cad, "Priority:");
	if(p) memcpy(prio, p, 12);

	if(isdigit(prio[10]))
		if(priority >= (prio[10] - 48)) {
			free(prio);
			return(1);
		}

	free(prio);
	return(0);
}

int
s2c_parse_ip(char *cad, char *ret)
{
	int len = 0;
	unsigned int enc = 1;
	regex_t *expr = NULL;
	regmatch_t *resultado = NULL;

	if((expr = (regex_t*)malloc(sizeof(regex_t))) == NULL) s2c_malloc_err();

	memset(expr, 0x00, sizeof(regex_t));

	if (regcomp(expr, REG_ADDR, REG_EXTENDED) !=0) {
		syslog(LOG_ERR | LOG_DAEMON, "%s - %s", LANG_ERR_REGEX, LANG_EXIT);
		s2c_exit_fail();
	}

	if((resultado = (regmatch_t*)malloc(sizeof(regmatch_t))) == NULL) s2c_malloc_err();

	memset(resultado, 0x00, sizeof(regmatch_t));
	
	if (regexec(expr, cad, 1, resultado, 0) != 0) enc = 0;
	
	if (enc != 0) {
		len = resultado->rm_eo - resultado->rm_so;
		memcpy(ret, cad + resultado->rm_so, len);
		ret[len]='\0';
	}
	
	free(resultado);
	regfree(expr);

	if(enc) return(1);
	else return(0);
}

void
s2c_parse_and_block(int dev, int priority, char *logfile, char *line, char *tablename, struct wlist_head *wh, struct blist_head *bh)
{
	char *ret = NULL;
	thread_log_t *log_data = NULL;

	if(!s2c_parse_priority(priority, line)) return;

	if((ret = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(ret, BUFMAX);

	if (!s2c_parse_ip(line, ret)) {
		free(ret);
		return;
	}

	if (!LIST_EMPTY(wh))
		if (s2c_parse_search_wl(ret, wh)) {
			free(ret);
			return;
	}

	if(!s2c_parse_and_block_blisted(ret, bh)) {
		if((log_data = (thread_log_t *)malloc(sizeof(thread_log_t))) == NULL) s2c_malloc_err();

		memset(log_data, 0x00, sizeof(thread_log_t));

		s2c_pf_block_log_check();

		pthread_mutex_lock(&thr_mutex);
		s2c_threads++;
		pthread_mutex_unlock(&thr_mutex);

		strlcpy(log_data->logfile, logfile, BUFMAX);
		strlcpy(log_data->logip, ret, BUFMAX);
		s2c_spawn_thread(s2c_pf_block_log, log_data);
	
		s2c_pf_block(dev, tablename, ret, wh, bh);
	}

	free(ret);
	return;
}

int
s2c_parse_load_wl_file(char *wlist_file, struct ipwlist *ipw1)
{
	char *cad = NULL, *ret = NULL;
	struct ipwlist *ipw2 = NULL;
	FILE *wlfile = NULL;


	if ((wlfile = fopen(wlist_file, "r")) == NULL) return(1);

	flockfile(wlfile);

	if((cad = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((ret = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(cad, BUFMAX);
	bzero(ret, BUFMAX);

	while(s2c_parse_line(cad, wlfile)) {
		if (s2c_parse_ip(cad, ret)) {

			if((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
			if((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();

			ipw2->waddr = cidr_from_str(ret);
			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}
	}

	funlockfile(wlfile);
	fclose(wlfile);

	free(cad);
	free(ret);
	return(0);
}

void
s2c_parse_load_wl_ifaces(struct ipwlist *ipw1)
{
	struct ipwlist *ipw2 = NULL;
	struct ifaddrs *ifaddr = NULL, *ifa = NULL;
	int n = 0;

	if (getifaddrs(&ifaddr) == -1) {
		syslog(LOG_DAEMON | LOG_ERR, "%s -%s", LANG_IFADDR_ERROR, LANG_EXIT);
		s2c_exit_fail();
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		if((ifa->ifa_addr)->sa_family == AF_INET) {
			if((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();

			memset(ipw2, 0x00, sizeof(struct ipwlist));

			if((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();

			ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}

	}

	freeifaddrs(ifaddr);
	return;
}

int
s2c_parse_load_bl(int dev, char *tablename, struct wlist_head *wh, struct blist_head *bh)
{
	char *cad = NULL, *ret = NULL;
	FILE *blfile = NULL;

	if ((blfile = fopen(bfile, "r")) == NULL) return(1);

	flockfile(blfile);

	if((cad = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();
	if((ret = (char *)malloc(sizeof(char)*BUFMAX)) == NULL) s2c_malloc_err();

	bzero(cad, BUFMAX);
	bzero(ret, BUFMAX);

	while(s2c_parse_line(cad, blfile))
		if (s2c_parse_ip(cad, ret)){
			if (!LIST_EMPTY(wh)){
				if (!s2c_parse_search_wl(ret, wh)) s2c_pf_block(dev, tablename, ret, wh, bh);
				else syslog(LOG_ERR | LOG_DAEMON, "%s %s %s - %s", LANG_BENT, ret, LANG_WL, LANG_WARN);
			} else s2c_pf_block(dev, tablename, ret, wh, bh);
		}

	funlockfile(blfile);
	fclose(blfile);

	free(cad);
	free(ret);
	return(0);
}

void
s2c_parse_load_wl(struct wlist_head *head)
{
	struct ipwlist *ipw1 = NULL, *ipw2 = NULL;
	struct ifreq *ifr = NULL;
	int fd = 0;

	if((ipw1 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();

	memset(ipw1, 0x00, sizeof(struct ipwlist));

	if((ipw1->waddr = cidr_alloc()) == NULL) s2c_malloc_err();

	ipw1->waddr = cidr_from_str("127.0.0.0/8");

	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipw1, elem);

	if(strcmp(extif, "all") == 0) {
		s2c_parse_load_wl_ifaces(ipw1);

	} else {
		if((ifr = (struct ifreq *)malloc(sizeof(struct ifreq))) == NULL) s2c_malloc_err();
		memset(ifr, 0x00, sizeof(struct ifreq));
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr->ifr_addr.sa_family = AF_INET;
		strlcpy(ifr->ifr_name, extif, IFNAMSIZ);
		if(ioctl(fd, SIOCGIFADDR, ifr) == -1){
			syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, extif, LANG_EXIT);
			s2c_exit_fail();
		}
		close(fd);
		free(ifr);

		if((ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist))) == NULL) s2c_malloc_err();
		if((ipw2->waddr = cidr_alloc()) == NULL) s2c_malloc_err();

		ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr);
		LIST_INSERT_AFTER(ipw1, ipw2, elem);
		ipw1 = ipw2;
	}

	if(s2c_parse_load_wl_file(PATH_RESOLV, ipw1)) {
		syslog(LOG_DAEMON | LOG_ERR, "%s %s - %s", LANG_NO_OPEN, PATH_RESOLV, LANG_WARN);
		return;
	}

	if(s2c_parse_load_wl_file(wfile, ipw1)) {
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

	if(ipcidr == NULL) s2c_malloc_err();

	ipcidr = cidr_from_str(ip);
	for(aux2=wl->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
		if(!cidr_contains(aux2->waddr, ipcidr)){
			cidr_free(ipcidr);
			return(1);
		}
	}

	cidr_free(ipcidr);
	return(0);
}
