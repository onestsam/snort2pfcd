<HTML>
<BODY>
<PRE>
<!-- Manpage converted by man2html 3.0.1 -->
.\"
.\" Expiretable functions from expiretable
.\" Copyright (c) 2005 Henrik Gustafsson &lt;henrik.gustafsson@fnord.se&gt;
.\"
.\" s2c_parse_line based in pfctl code (pfctl_radix.c)
.\" Copyright (c) Armin's Wolfermann
.\"
.\" s2c_pf_block functions are based
.\" on Armin's Wolfermann pftabled-1.03 functions.
.\"
.\" All rights reserved.
.\"
.\" Permission to use, copy, modify, and distribute this software for any
.\" purpose with or without fee is hereby granted, provided that the above
.\" copyright notice and this permission notice appear in all copies.
.\"
.\" THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
.\" WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
.\" MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
.\" ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
.\" WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
.\" ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
.\" OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
.\"
.\"
.Dd May 17, 2017
.Dt SNORT2PFCD 8
.Sh NAME
.Nm snort2pfcd
.Nd provides real-time blocking of ip addresses from snort alerts via packet filter firewall tables.
.Sh SYNOPSIS
.Nm snort2pfcd
.Op Fl e Ar External_Interface
.Op Fl w Ar Whitelist_File
.Op Fl b Ar Blacklist_File
.Op Fl W
.Op Fl B
.Op Fl D
.Op Fl F
.Op Fl Z
.Op Fl l Ar Log_File
.Op Fl a Ar Alert_File
.Op Fl p Ar Priority
.Op Fl r Ar Repeat_Offenses
.Op Fl t Ar Seconds
.Op Fl d Ar Pf_device
.Op Fl q Ar Seconds
.Op Fl m Ar Thr_max
.Op Fl v
.Op Fl h
.Sh DESCRIPTION
.Nm
.It Fl b Ar Blacklist_File
blacklist file, default is /usr/local/etc/snort/rules/iplists/default.blacklist.
.It Fl B 
If set, will prevent loading of the snort blacklist file.
.It Fl D
If set, will disable the DNS lookup functionality.
.It Fl F
Foreground mode. If set, will not daemonize.
.It Fl Z
If set, will prevent the whitelisting of entries in the /etc/resolv.conf file.
.It Fl l Ar Log_File
log file location, default is /var/log/snort2pfcd.log.
.It Fl a Ar Alert_File
snort alert file location, default is /var/log/snort/alert.
.It Fl p Ar Priority 
The priority level at which to block an ip addresses in the snort log. Default is 1. 
Lower priority includes higher priority, for example, -p 3 includes priorities 3, 2 and 1. 
.It Fl r Ar Repeat_Offenses
Number of times an ip address may commit an offense before being added to the packet filter block table. 
Default is 0. For example, -p 2 -r 2 specifies that any priority 1 or 2 snort alert for a given network address will be blocked only after 2 repeated snort alerts (3 snort alerts total). 
.It Fl t Ar Seconds 
The number of seconds to block an ip address, default is 60*60 or 1 hour.
.It Fl d Ar Pf_device
Packet filter device interface. Default is /dev/pf.
.It Fl q Ar Seconds
The number of seconds to wait before starting to parse the snort alert file. Useful if 
.Nm
is interfering with connection setup, especially shortly after boot. Default is 0.
.It Fl m Ar thr_max
Maximum number of DNS request threads. Default is 100.
.Nm
uses a non-blocking design to ensure that waiting for DNS names to resolve in the block log do not interfere with the blocking of snort alerts. Instead of the main program waiting, a new thread is spawned to do the waiting. Since connection speeds vary widely (100mb/s - &gt;40Gb/s) and servers also vary in terms of processing capability, the option exists to increase or decrease the maximum number of threads waiting for DNS requests. Once the maximum number of threads waiting for a DNS response is reached, logging will stop until an active thread exits. The main program however will continue its blocking function with a cessation in logging until a new thread can be spawned. 
.It Fl v
Increase verbosity.
.It Fl h
Show help.
.El
.Sh THEORY OF OPERATION
The snort intrusion detection system monitors network traffic and will generate an alert if this traffic matches a rule for a type of noteworthy activity.
.Nm
monitors this alert file and can then add the offending ip address to a packet filter block table. 
.Nm
provides the above options for the user to specify the conditions under which the offending address is added to the packet filter block table.
.Pp
Differentiating between benign and malicious network traffic is difficult and, unfortunately, snort generates a fair amount of false-positives. Also, the snort IDS primary function is to log noteworthy network traffic and its authors did not necessarily intend for the logged addresses to be blocked. This being said, snorts rules are highly configurable and can be adjusted for more appropriate functioning in this context. To assist the user with filtering network traffic produced by various network entities, 
.Nm
will automatically resolve the offending ip address and display the DNS name in the 
.Nm
block log. Should the user decide that the offending address is trustworthy, the user can add the address, or alternatively, research and add the entire CIDR address block assigned to that network entity, to the whitelist. Whitelisted addresses or CIDR address blocks generating a snort alert will not be added to the packet filter block table.
.Pp
.Nm
also loads the snort community supplied blacklist file into a separate packet filter block table by default. Table entries are named "snort2pfcd" for dynamic entries which can be viewed with "pfctl -t snort2pfcd -T show". Static entries loaded from the community provided snort blacklist are populated within the "snort2pfcd_static" table which can be viewed with "pfctl -t snort2pfcd_static -T show".
.Pp
.Sh Blacklist
.Pp
Blacklist entries provided by the snort community contain a list of single ip addresses and 
.Nm
will only accept entries in this format (e.g. 192.168.0.1). Each entry should be on a separate line.
.Sh NOTES
While
.Nm
will parse the default snort alert file, this can produce less than real-time blocking given the burden being placed on snort especially over an active, fast or low-latency connection. The author would strongly recommend using a spooler like barnyard2 to output the text alerts from the snort unified2 binary output.
.Pp
By default, the user-supplied whitelist is prepended with the addresses of all of the local interfaces as the handling of these addresses are usually specified by more complex packet filter rules and simply blocking these addresses can cause problems with certain configurations.
.Pp
The user-supplied whitelist can also be prepended with the address of the external interface only for paranoid configurations. Lo0 is always whitelisted.
.Pp
.Nm
also automatically whitelists addresses found within the /etc/resolv.conf file as these addresses should also be handled by specific packet filter rules.
.Pp
A static blacklist table is also maintained and populated within the packet filter firewall with the addresses found within the /usr/local/etc/snort/rules/iplists/default.blacklist file. These addresses can be supplied by the user or automatically populated with addresses supplied by the snort community.
.Sh CREDITS
This program is based on snort2c written by Antonio Benojar which was based on the original snort2pf perl script written by Stephan Schmieder. Expiration of entries use Henrik Gustafsson's expiretable functions. Blocking functionality based on pfctl and pftabled functions by Armin Wolfermann.
.Sh SEE ALSO
.Xr pf 4 ,
.Xr pfctl 8 ,
.Xr snort 8 ,
.Xr expiretable 1 ,
.Xr libcidr 3 ,
.Sh AUTHORS
Samee Shahzada &lt;onestsam@gmail.com&gt;
</PRE>
<HR>
<ADDRESS>
Man(1) output converted with
<a href="http://www.oac.uci.edu/indiv/ehood/man2html.html">man2html</a>
</ADDRESS>
</BODY>
</HTML>
