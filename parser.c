/*
 * snort2pfcd
 * Copyright (c) 2016 Samee Shahzada <onestsam@gmail.com>
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
#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <errno.h>
#include <syslog.h>
#include <libcidr.h>
#include <ifaddrs.h>
#include <pthread.h>

#include "defdata.h"
#include "spfc.h"
#include "parser.h"

int
s2c_parse_and_block_blisted(char *ret, struct blist_head *blist)
{
	struct ipblist *aux2, *ipb = NULL;

	ipb = (struct ipblist*)malloc(sizeof(struct ipblist));
	if(ipb == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A01 - exit");
		exit(EXIT_FAILURE);
	}
	memcpy(ipb->baddr, ret, LISTMAX);

	if(blist->lh_first == NULL){
		LIST_INIT(blist);
		LIST_INSERT_HEAD(blist, ipb, elem);
	} else {
		for(aux2=blist->lh_first; aux2 !=NULL; aux2=aux2->elem.le_next) {
			if(!strcmp(aux2->baddr, ret)){
				free(ipb);
				return(1);
			} else if(!aux2->elem.le_next) {
				LIST_INSERT_AFTER(aux2, ipb, elem);
				return(0);
			}
		}
	}	

	return(0);
}

int
s2c_parse_line(char buf[LISTMAX] , FILE* wfile)
{
	static char     next_ch = ' ';
        int             i = 0;
        
	if (feof(wfile)) {
	        return (0);
	}                                
	do {
		next_ch = fgetc(wfile);
		if (i < LISTMAX)
	        	buf[i++] = next_ch;
	} while (!feof(wfile) && !isspace(next_ch));
	if (i >= LISTMAX) {
		return (-1);
	}		                 
	
	buf[i] = '\0';
	return(1);
}

int
s2c_parse_priority(int priority, char *cad)
{
	char prio[LISTMAX];
	char *p;

	bzero(prio, LISTMAX);

	p = strstr(cad, "Priority:");
	if(p) memcpy(prio, p, 12);

	if(isdigit(prio[10]))
		if(priority >= (prio[10] - 48))
			return(1);

	return(0);
}

int
s2c_parse_ip(char *cad, char ret[LISTMAX])
{
	int len;
	unsigned int enc=1;
	regex_t *expr;
	regmatch_t *resultado;
	expr = (regex_t*)malloc(sizeof(regex_t));

	if(expr == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A02 - exit");
                exit(EXIT_FAILURE);	
	}

	bzero(ret, LISTMAX);
	
	resultado = (regmatch_t*)malloc(sizeof(regmatch_t));
	if(resultado == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A03 - exit");
		exit(EXIT_FAILURE);
		}
	
	if (regcomp(expr, REG_ADDR, REG_EXTENDED) !=0) {
		syslog(LOG_ERR | LOG_DAEMON, "error compiling regex expr - exit");
		exit(EXIT_FAILURE);
	}
	if (regexec(expr, cad, 1, resultado, 0) !=0) 
		enc=0;
	
	if (enc !=0) {
		len = resultado->rm_eo - resultado->rm_so;
		memcpy(ret, cad + resultado->rm_so, len);
		ret[len]='\0';
	}
	
	free(resultado);
	regfree(expr);

	if(enc)
		return(1);
	else {
		errno = EINVAL;
		return(0);
	}
}

void
s2c_parse_and_block(int dev, int priority, char *logfile, char *line, char *tablename, struct wlist_head *wh, struct blist_head *bh)
{
	char ret[LISTMAX];
	thread_log_t *log_data;

	log_data = (thread_log_t *)malloc(sizeof(thread_log_t));

	bzero(ret, LISTMAX);
	memset(log_data, 0x00, sizeof(thread_log_t));

	if(!s2c_parse_priority(priority, line))
		return;

	if (!s2c_parse_ip(line, ret))
		return;

	if (!LIST_EMPTY(wh))
		if (s2c_parse_search_wl(ret, wh))
			return;

	/* Maintain out own blist and log once */
	if(!s2c_parse_and_block_blisted(ret, bh)){
		strlcpy(log_data->logfile, logfile, LISTMAX);
		strlcpy(log_data->logip, ret, LISTMAX);
		s2c_spawn_thread(s2c_pf_block_log, log_data);
	}

	s2c_pf_block(dev, tablename, ret);

	return;
}

int
s2c_parse_load_wl_file(char *wlist_file, struct ipwlist *ipw1)
{
	char cad[LISTMAX];
	char ret[LISTMAX];
	struct ipwlist *ipw2 = NULL;
	FILE *wfile = NULL;

	bzero(cad, LISTMAX);
	bzero(ret, LISTMAX);

	wfile = fopen(wlist_file, "r");

	if (wfile == NULL)
		return(1);

	flockfile(wfile);

	while(s2c_parse_line(cad, wfile)) {
		if (s2c_parse_ip(cad, ret)) {
			ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist));
			if(ipw2 == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error A04 - exit");
				exit(EXIT_FAILURE);
			}
			ipw2->waddr = cidr_alloc();
			if(ipw2->waddr == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error A05 - exit");
				exit(EXIT_FAILURE);
			}

			ipw2->waddr = cidr_from_str(ret);
			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}
	}

	funlockfile(wfile);
	fclose(wfile);

	return(0);
}

void
s2c_parse_load_wl_ifaces(struct ipwlist *ipw1)
{
	struct ipwlist *ipw2 = NULL;
	struct ifaddrs *ifaddr, *ifa;
	int n;

	if (getifaddrs(&ifaddr) == -1) {
		syslog(LOG_DAEMON | LOG_ERR, "ifaddr error - exit");
		exit(EXIT_FAILURE);
	}

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
		if (ifa->ifa_addr == NULL)
			continue;

		if((ifa->ifa_addr)->sa_family == AF_INET) {
			ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist));
			if(ipw2 == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error A06 - exit");
				exit(EXIT_FAILURE);
			}
			ipw2->waddr = cidr_alloc();
			if(ipw2->waddr == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error A07 - exit");
				exit(EXIT_FAILURE);
			}

			ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
			LIST_INSERT_AFTER(ipw1, ipw2, elem);
			ipw1 = ipw2;
		}

	}

	freeifaddrs(ifaddr);

	return;
}

int
s2c_parse_load_bl(int dev, char *tablename, char *namefile, struct wlist_head *wh)
{
	char cad[LISTMAX];
	char ret[LISTMAX];
	struct stat info;
	struct ifreq ifr;
	FILE *bfile = NULL;

	bzero(cad, LISTMAX);
	bzero(ret, LISTMAX);
	memset(&info, 0x00, sizeof(struct stat));
	memset(&ifr, 0x00, sizeof(struct ifreq));
	lstat(namefile, &info);

	if (info.st_mode & S_IFDIR) {
		syslog(LOG_ERR | LOG_DAEMON, "bfile is a directory: %s - exit", namefile);
		exit(EXIT_FAILURE);
	}

	if (s2c_pf_ruleadd(dev, tablename) == 1) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to add ruletable - exit");
		exit(EXIT_FAILURE);
	}

	bfile = fopen(namefile, "r");

	if (bfile == NULL)
		return(-1);

	flockfile(bfile);

	while(s2c_parse_line(cad, bfile))
		if (s2c_parse_ip(cad, ret)){
			if (!LIST_EMPTY(wh)){
				if (!s2c_parse_search_wl(ret, wh)){
					s2c_pf_block(dev, tablename, ret);
				} else {
					syslog(LOG_ERR | LOG_DAEMON, "Blacklist entry %s is whitelisted - warning", ret);
				}
			} else {
				s2c_pf_block(dev, tablename, ret);
			}
		}

	funlockfile(bfile);
	fclose(bfile);

	return (0);
}

int
s2c_parse_load_wl(char *namefile, char *extif, struct wlist_head *head)
{
	struct ipwlist *ipw1, *ipw2 = NULL;
	struct stat info;
	struct ifreq ifr;
	int fd;
	
	memset(&info, 0x00, sizeof(struct stat));
	memset(&ifr, 0x00, sizeof(struct ifreq));
	lstat(namefile, &info);

	if (info.st_mode & S_IFDIR) {
		syslog(LOG_ERR | LOG_DAEMON, "wfile is a directory: %s - exit", namefile);
		exit(EXIT_FAILURE);
	} 

	ipw1 = (struct ipwlist*)malloc(sizeof(struct ipwlist));
	if(ipw1 == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A08 - exit");
		exit(EXIT_FAILURE);
	}

	ipw1->waddr = cidr_alloc();
	if(ipw1->waddr == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A09 - exit");
		exit(EXIT_FAILURE);
	}

	ipw1->waddr = cidr_from_str("127.0.0.0/8");

	LIST_INIT(head);
	LIST_INSERT_HEAD(head, ipw1, elem);

	if(strcmp(extif, "all") == 0) {
		s2c_parse_load_wl_ifaces(ipw1);

	} else {
		fd = socket(AF_INET, SOCK_DGRAM, 0);
		ifr.ifr_addr.sa_family = AF_INET;
		strncpy(ifr.ifr_name, extif, IFNAMSIZ-1);
		if(ioctl(fd, SIOCGIFADDR, &ifr) == -1){
			syslog(LOG_DAEMON | LOG_ERR, "Error accessing %s - exit", extif);
			exit(EXIT_FAILURE);
		}
		close(fd);

		ipw2 = (struct ipwlist*)malloc(sizeof(struct ipwlist));
		if(ipw2 == NULL) {
			syslog(LOG_DAEMON | LOG_ERR, "malloc error A10 - exit");
			exit(EXIT_FAILURE);
		}

		ipw2->waddr = cidr_alloc();
		if(ipw2->waddr == NULL) {
                	syslog(LOG_DAEMON | LOG_ERR, "malloc error A11 - exit");
			exit(EXIT_FAILURE);
		}

		ipw2->waddr = cidr_from_inaddr(&((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
		LIST_INSERT_AFTER(ipw1, ipw2, elem);
		ipw1 = ipw2;
	}

	if(s2c_parse_load_wl_file("/etc/resolv.conf", ipw1))
		return(-1);
	if(s2c_parse_load_wl_file(namefile, ipw1))
		return(-1);

	return(0);
}

int
s2c_parse_search_wl(char *ip, struct wlist_head *wl)
{
	struct ipwlist *aux2;
	CIDR *ipcidr = cidr_alloc();

	if(ipcidr == NULL) {
		syslog(LOG_DAEMON | LOG_ERR, "malloc error A12 - exit");
		exit(EXIT_FAILURE);
	}

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
