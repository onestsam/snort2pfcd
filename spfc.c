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


#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <netdb.h>
#include <pthread.h>

#include "spfc.h"
#include "ioctl_helpers.h"

long
lmax(long a,long b) {
        return (a > b)?a:b;
}

long
lmin(long a,long b) {
        return (a < b)?a:b;
}

void
*s2c_pf_expiretable(void *arg)
{
	struct pfr_astats *astats;
	struct pfr_table target;
	struct pfr_addr *del_addrs_list;
	int astats_count, del_addrs_count, del_addrs_result;
	struct thread_expt_t *data = (struct thread_expt_t *)arg;

	unsigned long age = 60*60*3;
	long min_timestamp, oldest_entry;
	int local_dev, i = 0;
	int flags = PFR_FLAG_FEEDBACK;

	if(data->t) age = (unsigned long)data->t;
	local_dev = data->dev;

	/* already been strlcpy'd */
	memcpy(target.pfrt_name, data->tablename, PF_TABLE_NAME_SIZE);

	while (1) {
		memset(&target, 0x00, sizeof(struct pfr_table));
		min_timestamp = (long)time(NULL) - age;
		oldest_entry = time(NULL);
		astats_count = radix_get_astats(local_dev, &astats, &target,0);

		if (astats_count > 0) {

			del_addrs_list = NULL;
			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astats[i].pfras_tzero <= min_timestamp) {
					del_addrs_count++;
				}
				else {
					oldest_entry = lmin(oldest_entry, astats[i].pfras_tzero);
				}
			}

			if ((del_addrs_list = malloc(del_addrs_count * sizeof(struct pfr_addr))) == NULL) {
				syslog(LOG_DAEMON | LOG_ERR, "malloc error B01 - exit");
				exit(EXIT_FAILURE);
				}

			del_addrs_count = 0;

			for (i = 0; i < astats_count; i++) {
				if (astats[i].pfras_tzero <= min_timestamp) {
					del_addrs_list[del_addrs_count] = astats[i].pfras_a;
					del_addrs_list[del_addrs_count].pfra_fback = 0;
					del_addrs_count++;
				}
			}

			if (del_addrs_count > 0) {
				del_addrs_result = radix_del_addrs(local_dev, &target, del_addrs_list, del_addrs_count, flags);
				free(del_addrs_list);
			}
			free(astats);
		}
		else if (astats_count == 0) {
			free(astats);
		}

		sleep(60);
	}
}

void
s2c_spawn_expt_thread(void *data)
{
	pthread_t *expt_thr;
	pthread_attr_t *expt_attr;
	thread_expt_t *expt_data;

	expt_thr = (pthread_t *)malloc(sizeof(pthread_t));
	expt_attr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));
	expt_data = (thread_expt_t *)data;

	memset(expt_thr, 0x00, sizeof(pthread_t));
	memset(expt_attr, 0x00, sizeof(pthread_attr_t));

	if(pthread_attr_init(expt_attr)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to init expiretable thread attributes - warning");

	} else if(pthread_attr_setdetachstate(expt_attr, PTHREAD_CREATE_DETACHED)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to set expiretable thread attributes - warning");

	} else if(pthread_create(expt_thr, expt_attr, s2c_pf_expiretable, expt_data))
		syslog(LOG_ERR | LOG_DAEMON, "unable to launch expiretable thread - warning");


	free(expt_attr);
	free(expt_thr);
	return;
}


void
s2c_spawn_log_thread(void *data)
{
	pthread_t *log_thr;
	pthread_attr_t *log_attr;
	thread_log_t *log_data;

	log_thr = (pthread_t *)malloc(sizeof(pthread_t));
	log_attr = (pthread_attr_t *)malloc(sizeof(pthread_attr_t));
	log_data = (thread_log_t *)data;

	memset(log_thr, 0x00, sizeof(pthread_t));
	memset(log_attr, 0x00, sizeof(pthread_attr_t));

	if(pthread_attr_init(log_attr)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to init log thread attributes - warning");

	} else if(pthread_attr_setdetachstate(log_attr, PTHREAD_CREATE_DETACHED)) {
		syslog(LOG_ERR | LOG_DAEMON, "unable to set log thread attributes - warning");

	} else if(pthread_create(log_thr, log_attr, s2c_pf_block_log, log_data))
		syslog(LOG_ERR | LOG_DAEMON, "unable to launch log thread - warning");


	free(log_attr);
	free(log_thr);
	return;
}

int 
s2c_pf_block(int dev, char *tablename, char *ip) 
{ 
	struct pfioc_table io; 
    	struct pfr_table table; 
      	struct pfr_addr addr; 
      	struct in_addr net_addr;
      
        memset(&io,    0x00, sizeof(struct pfioc_table)); 
        memset(&table, 0x00, sizeof(struct pfr_table)); 
        memset(&addr,  0x00, sizeof(struct pfr_addr));
	memset(&net_addr,  0x00, sizeof(struct in_addr));

        memcpy(table.pfrt_name, tablename, PF_TABLE_NAME_SIZE); 
        inet_aton(ip, (struct in_addr *)&net_addr);
        memcpy(&addr.pfra_ip4addr.s_addr, &net_addr, sizeof(struct in_addr));
        
        addr.pfra_af  = AF_INET; 
        addr.pfra_net = 32; 
        
        io.pfrio_table  = table; 
        io.pfrio_buffer = &addr; 
        io.pfrio_esize  = sizeof(struct pfr_addr); 
        io.pfrio_size   = 1; 
        
        if (ioctl(dev, DIOCRADDADDRS, &io)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRADDADDRS - ioctl error - exit");
		exit(EXIT_FAILURE);
        }

	return(0);
}

void
*s2c_pf_block_log(void *arg)
{
	char message[WLMAX];
	char local_logip[WLMAX];
	char local_logfile[WLMAX];
	char hbuf[NI_MAXHOST];
	long timebuf = 0;
	FILE *lfile = NULL;
	struct sockaddr sa;
	struct sockaddr_in *sin;
	struct thread_log_t *data = (struct thread_log_t *)arg;

	bzero(message, WLMAX);
	bzero(hbuf, NI_MAXHOST);
	bzero(local_logip, WLMAX);
	bzero(local_logfile, WLMAX);
	memset(&sa,  0x00, sizeof(struct sockaddr_in));

	memcpy(local_logip, data->logip, WLMAX);
	memcpy(local_logfile, data->logfile, WLMAX);

	timebuf = time(NULL);

	sa.sa_family = AF_INET;
	sin = (struct sockaddr_in *) &sa;

	if(inet_pton(AF_INET, local_logip, &((struct sockaddr_in *)&sa)->sin_addr)){
		if (getnameinfo(&sa, sizeof(sa), hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == EAI_NONAME)
			strlcpy(hbuf, "Unresolvable", 13);
	}

	sprintf(message, "%s (%s) not whitelisted, added to block table %s", local_logip, hbuf, asctime(localtime(&timebuf)));

	lfile = fopen(local_logfile, "a");
	flockfile(lfile);
	fputs(message, lfile);
	funlockfile(lfile);
	fclose(lfile);

	free(data);
	pthread_exit(NULL);
}

int 
s2c_pf_tbladd(int dev, char * tablename) 
{
	struct pfioc_table io;
	struct pfr_table table;

	memset(&io,    0x00, sizeof(struct pfioc_table));
	memset(&table, 0x00, sizeof(struct pfr_table));

	memcpy(table.pfrt_name, tablename, PF_TABLE_NAME_SIZE);
	table.pfrt_flags = PFR_TFLAG_PERSIST;

	io.pfrio_buffer = &table; 
	io.pfrio_esize  = sizeof(struct pfr_table); 
	io.pfrio_size   = 1; 

	if (ioctl(dev, DIOCRADDTABLES, &io)) { 
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRADDTABLES - ioctl error - exit");
		return(1);
	}
	return(0); 
}

int
s2c_pf_ruleadd(int dev, char *tablename)
{
	struct pfioc_rule     io_rule;
	struct pfioc_pooladdr io_paddr;

	memset(&io_rule,  0x00, sizeof(struct pfioc_rule));
	memset(&io_paddr, 0x00, sizeof(struct pfioc_pooladdr));

	if(!s2c_pf_intbl(dev, tablename))
		if(s2c_pf_tbladd(dev, tablename))
			return(1);

	io_rule.rule.direction = PF_IN;
	io_rule.rule.action = PF_DROP;
	io_rule.rule.src.addr.type = PF_ADDR_TABLE;
	io_rule.rule.rule_flag = PFRULE_RETURN;
	memcpy(io_rule.rule.src.addr.v.tblname, tablename, sizeof(io_rule.rule.src.addr.v.tblname));

	io_rule.action = PF_CHANGE_GET_TICKET;

	if (ioctl(dev, DIOCCHANGERULE, &io_rule)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCCHANGERULE - ioctl error - exit");
		exit(EXIT_FAILURE);
	}	

	if (ioctl(dev, DIOCBEGINADDRS, &io_paddr)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCBEGINADDRS - ioctl error - exit");
		exit(EXIT_FAILURE);
	}

	io_rule.pool_ticket = io_paddr.ticket;
	io_rule.action = PF_CHANGE_ADD_TAIL;

	if (ioctl(dev, DIOCCHANGERULE, &io_rule)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCCHANGERULE - ioctl error - exit");
		exit(EXIT_FAILURE);
	}

	return(0);
}

int 
s2c_pf_intbl(int dev, char *tablename)
{
	int i;
	struct pfioc_table io;
	struct pfr_table *table_aux = NULL;
	
	memset(&io, 0x00, sizeof(struct pfioc_table));
	
	io.pfrio_buffer = table_aux;
	io.pfrio_esize  = sizeof(struct pfr_table);
	io.pfrio_size   = 0;
	
	if(ioctl(dev, DIOCRGETTABLES, &io)) { 
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRGETTABLES - ioctl error - exit");
		exit(EXIT_FAILURE);
	}
	
	table_aux = (struct pfr_table*)malloc(sizeof(struct pfr_table)*io.pfrio_size);
	if(table_aux == NULL){
		syslog(LOG_DAEMON | LOG_ERR, "malloc error B02 - exit");
		exit(EXIT_FAILURE);
	}

	io.pfrio_buffer = table_aux;
	io.pfrio_esize = sizeof(struct pfr_table);

	if(ioctl(dev, DIOCRGETTABLES, &io)) {
		syslog(LOG_DAEMON | LOG_ERR, "DIOCRGETTABLES - ioctl error - exit");
		exit(EXIT_FAILURE);
	}

	for(i=0; i< io.pfrio_size; i++) {
		if (!strcmp(table_aux[i].pfrt_name, tablename)){
			free(table_aux);
			return(1);
		}
	}

	free(table_aux);
	return(0);
}
