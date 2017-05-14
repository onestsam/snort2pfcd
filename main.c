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

#include "defdata.h"
#include "version.h"


int
main(int argc, char **argv)
{
	extern char *optarg;
	extern int optind;
	int F = 0, ch = 0, w = 0, b = 0, a = 0, l = 0, e = 0, d = 0, q = 0;
	unsigned long t = 0;
	char *alertfile = NULL, *nmpfdev = NULL;
	wbhead_t *wbhead = NULL;
	loopdata_t *loopdata = NULL;

	if ((wfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((bfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((alertfile = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((nmpfdev = (char *)malloc(sizeof(char)*NMBUFSIZ)) == NULL) s2c_malloc_err();
	if ((extif = (char *)malloc(sizeof(char)*IFNAMSIZ)) == NULL) s2c_malloc_err();
	if ((loopdata = (loopdata_t *)malloc(sizeof(loopdata_t))) == NULL) s2c_malloc_err();

	bzero(wfile, NMBUFSIZ);
	bzero(bfile, NMBUFSIZ);
	bzero(alertfile, NMBUFSIZ);
	bzero(nmpfdev, NMBUFSIZ);
	bzero(extif, IFNAMSIZ);
	memset(loopdata, 0x00, sizeof(loopdata_t));

	loopdata->priority = 1;
	loopdata->thr_max = THRMAX;
	strlcpy(loopdata->tablename, __progname, PF_TABLE_NAME_SIZE);
	
	s2c_init();
	while ((ch = getopt(argc, argv, "w:p:q:m:r:vWDFBZb:a:l:e:t:d:h")) != -1)
		switch(ch) {
			case 'w': strlcpy(wfile, optarg, NMBUFSIZ); w = 1; break;
			case 'b': strlcpy(bfile, optarg, NMBUFSIZ); b = 1; break;
			case 'W': loopdata->W = 1; break;
			case 'B': loopdata->B = 1; break;
			case 'D': loopdata->D = 1; break;
			case 'Z': loopdata->Z = 1; break;
			case 'v': v = 1; break;
			case 'F': F = 1; break;
			case 'a': strlcpy(alertfile, optarg, NMBUFSIZ); a = 1; break;
			case 'd': strlcpy(nmpfdev, optarg, NMBUFSIZ); d = 1; break;
			case 'l': strlcpy(loopdata->logfile, optarg, NMBUFSIZ); l = 1; break;
			case 'e': strlcpy(extif, optarg, IFNAMSIZ); e = 1; break;
			case 't': if ((t = optnum("t", optarg)) == -1) usage(); break;
			case 'q': if ((q = optnum("q", optarg)) == -1) usage(); break;
			case 'p':
				if ((loopdata->priority = optnum("p", optarg)) == -1) usage(); 
				if (!loopdata->priority) loopdata->priority = 1; break;
			case 'm':
				if ((loopdata->thr_max = optnum("m", optarg)) == -1) usage();
				if (!loopdata->thr_max) loopdata->thr_max = THRMAX; break;
			case 'r': if ((loopdata->repeat_offenses = optnum("r", optarg)) == -1) usage(); break;
			case 'h': usage();
			case '?': usage();
			default: usage();
		}
	
	argc -= optind;
	argv += optind;

	if (!w) strlcpy(wfile, PATH_WHITELIST, NMBUFSIZ);
	if (!b) strlcpy(bfile, PATH_BLACKLIST, NMBUFSIZ);
	if (!a) strlcpy(alertfile, PATH_ALERT, NMBUFSIZ);
	if (!d) strlcpy(nmpfdev, PFDEVICE, NMBUFSIZ);
	if (!e) strlcpy(extif, "all", IFNAMSIZ);
	if (!l) {
		strlcpy(loopdata->logfile, PATH_LOG, NMBUFSIZ);
		strlcat(loopdata->logfile,  __progname, NMBUFSIZ);
		strlcat(loopdata->logfile, ".log", NMBUFSIZ);
	}

	if (v) fprintf(stdout, "%s version %s\n", __progname, VERSION);
	if(!F) s2c_daemonize();
	if (q) sleep(q);

	loopdata->dev = s2c_open_pf(nmpfdev);
	loopdata->fd = s2c_open_file(alertfile);

	if ((wbhead = (wbhead_t *)malloc(sizeof(wbhead_t))) == NULL) s2c_malloc_err();
	memset(wbhead, 0x00, sizeof(wbhead_t));

	s2c_log_init(loopdata->logfile);
	s2c_db_init(loopdata, &wbhead->whead);
	s2c_thr_init(loopdata);

	while (1) {
		s2c_kevent_loop(loopdata, &wbhead->whead, &wbhead->bhead);
		s2c_wbhead_reset(wbhead);
		s2c_db_init(loopdata, &wbhead->whead);
	}

	close(loopdata->dev); close(loopdata->fd);
	free(loopdata); free(wbhead); free(wfile); free(bfile); free(extif);
	closelog();
	return(0);
}
