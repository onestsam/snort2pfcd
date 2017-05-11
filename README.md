# snort2pfcd
v1.9
<!-- Creator     : groff version 1.19.2 -->
<!-- CreationDate: Thu May 11 15:42:32 2017 -->
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
"http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
<meta name="generator" content="groff -Thtml, see www.gnu.org">
<meta http-equiv="Content-Type" content="text/html; charset=US-ASCII">
<meta name="Content-Style" content="text/css">
</head>
<body>

<hr>


<p valign="top">SNORT2PFCD(8) FreeBSD System
Manager&rsquo;s Manual SNORT2PFCD(8)</p>

<p style="margin-top: 1em" valign="top"><b>NAME</b></p>

<p style="margin-left:6%;"><b>snort2pfcd</b> &mdash;
provides real-time blocking of ip addresses from snort
alerts via packet filter firewall tables.</p>


<p style="margin-top: 1em" valign="top"><b>SYNOPSIS</b></p>

<p style="margin-left:21%;"><b>snort2pfcd</b>
[<b>&minus;e&nbsp;</b><i>External_Interface</i>]
[<b>&minus;w&nbsp;</b><i>Whitelist_File</i>]
[<b>&minus;b&nbsp;</b><i>Blacklist_File</i>]
[<b>&minus;W</b>] [<b>&minus;B</b>] [<b>&minus;D</b>]
[<b>&minus;l&nbsp;</b><i>Log_File</i>]
[<b>&minus;a&nbsp;</b><i>Alert_File</i>]
[<b>&minus;p&nbsp;</b><i>Priority</i>]
[<b>&minus;r&nbsp;</b><i>Repeat_Offenses</i>]
[<b>&minus;t&nbsp;</b><i>Seconds</i>]
[<b>&minus;d&nbsp;</b><i>pf_device</i>]
[<b>&minus;m&nbsp;</b><i>Thr_max</i>] [<b>&minus;v</b>]
[<b>&minus;h</b>]</p>


<p style="margin-top: 1em" valign="top"><b>DESCRIPTION</b></p>

<p style="margin-left:6%;"><b>snort2pfcd</b> Analyzes snort
alert output and blocks ip addresses for a given snort
priority using packet filter table entries for a specified
period of time. A whitelist is specified to exclude local
and trusted ip address from being blocked. <b>snort2pfcd</b>
also preloads the community maintained and supplied snort
blacklist by default. The whitelist and blacklist files are
monitored and <b>snort2pfcd</b> automatically reloads and
updates the tables when changes are made to the files.</p>

<p style="margin-left:6%; margin-top: 1em">The options are
as follows:</p>

<p style="margin-top: 1em" valign="top"><b>&minus;e</b>
<i>External_Interface</i></p>

<p style="margin-left:17%;">external interface e.g. eth0 or
&quot;all&quot; to whitelist all interfaces, default is to
whitelist all interfaces.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;w</b>
<i>Whitelist_File</i></p>

<p style="margin-left:17%;">whitelist file, default is
/usr/local/etc/snort/rules/iplists/default.whitelist.</p>


<p style="margin-top: 1em" valign="top"><b>&minus;W</b></p>

<p style="margin-left:17%; margin-top: 1em">If set, will
prevent loading of any whitelist file.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;b</b>
<i>Blacklist_File</i></p>

<p style="margin-left:17%;">blacklist file, default is
/usr/local/etc/snort/rules/iplists/default.blacklist.</p>


<p style="margin-top: 1em" valign="top"><b>&minus;B</b></p>

<p style="margin-left:17%; margin-top: 1em">If set, will
prevent loading of the snort blacklist file.</p>


<p style="margin-top: 1em" valign="top"><b>&minus;D</b></p>

<p style="margin-left:17%; margin-top: 1em">If set, will
disable the DNS lookup functionality.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;l</b>
<i>Log_File</i></p>

<p style="margin-left:17%;">log file, default is
/var/log/snort2pfcd.log.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;a</b>
<i>Alert_File</i></p>

<p style="margin-left:17%;">snort alert file, default is
/var/log/snort/alert.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;p</b>
<i>Priority</i></p>

<p style="margin-left:17%;">The priority level to block ip
addresses in snort logs, default is 1. Lower priority
includes higher priority, for example, -p 3 includes
priorities 3, 2 and 1.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;r</b>
<i>Repeat_Offenses</i></p>

<p style="margin-left:17%;">Number of times an ip address
may commit an offense before being added to pf block table.
Default is 0. For example, -p 2 -r 2 specifies that priority
1 or 2 snort alerts will be blocked only after 2 repeated
snort alerts (3 snort alerts total).</p>

<p style="margin-top: 1em" valign="top"><b>&minus;t</b>
<i>Seconds</i></p>

<p style="margin-left:17%;">The number of seconds to block
an ip address, default is 60*60 or 1 hour.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;d</b>
<i>pf_device</i></p>

<p style="margin-left:17%;">Packet filter device interface.
Default is /dev/pf.</p>

<p style="margin-top: 1em" valign="top"><b>&minus;m</b>
<i>thr_max</i></p>

<p style="margin-left:17%;">Maximum number of DNS request
threads. Default is 100. <b>snort2pfcd</b> uses a
non-blocking design to ensure that waiting for DNS names to
resolve in the block log do not interere with
<b>snort2pfcd</b> blocking of snort alerts. Instead of the
main program waiting, a new thread is spun to do the
waiting. Since connection speeds vary widely (100mb/s -
&gt;40Gb/s) and servers also vary in terms of processing
capability, the option exists to increase or decrease the
maximum number of threads waiting for DNS requests.</p>


<p style="margin-top: 1em" valign="top"><b>&minus;v</b></p>

<p style="margin-left:17%; margin-top: 1em">Increase
verbosity.</p>


<p style="margin-top: 1em" valign="top"><b>&minus;h</b></p>

<p style="margin-left:17%; margin-top: 1em">Show help.</p>

<p style="margin-top: 1em" valign="top"><b>THEORY OF
OPERATION</b></p>

<p style="margin-left:6%;">The snort intrusion detection
system monitors network traffic and will generate an alert
if this traffic matches a rule for a type of malicious
activity. <b>snort2pfcd</b> monitors this alert file and can
then add the offending ip address to a packet filter block
table. <b>snort2pfcd</b> provides the above options for the
user to specify the conditions under which the offending
address is added to the packet filter block table.</p>

<p style="margin-left:6%; margin-top: 1em">Differentiating
between benign and malicious network traffic is difficult
and, unfortunately, snort generates a fair amount of
false-positives. One will find that many established and
trusted websites will also produce network traffic that
appears (or is genuinely) malicious. To assist the user with
filtering network traffic produced by various network
entities, <b>snort2pfcd</b> will automatically resolve the
offending ip address and display the DNS name in the
<b>snort2pfcd</b> block log. Should the user decide that the
offending address is trustworthy, the user can add the
address, or alternatively, research and add the entire CIDR
address block assigned to that network entity, to the
whitelist. Whitelisted addresses or CIDR address blocks
generating a snort alert will not be added to the packet
filter block table.</p>


<p style="margin-left:6%; margin-top: 1em"><b>snort2pfcd</b>
also loads the snort community supplied blacklist file into
a separate packet filter block table by default. Table
entries are named &quot;snort2pfcd&quot; for dynamic entries
which can be viewed with &quot;pfctl -t snort2pfcd -T
show&quot;. Static entries loaded from the community
provided snort blacklist are populated within the
&quot;snort2pfcd_static&quot; table which can be viewed with
&quot;pfctl -t snort2pfcd_static -T show&quot;.</p>

<p style="margin-left:6%; margin-top: 1em">At no time
should <b>snort2pfcd</b> need to be restarted.
<b>snort2pfcd</b> will repopulate its packet filter tables
if pf is restarted. <b>snort2pfcd</b> also monitors the
whitelist and blacklist files for changes. Changes applied
to these files are automatically reloaded and applied to the
running <b>snort2pfcd</b> processes.</p>

<p style="margin-top: 1em" valign="top"><b>FILES <br>
Whitelist</b></p>

<p style="margin-left:6%;">Whitelist entries can be single
ip addressess (e.g. 192.168.0.1) or blocks of addresses in
CIDR format (e.g. 192.168.0.0/24). Each entry should be on a
separate line.</p>


<p style="margin-top: 1em" valign="top"><b>Blacklist</b></p>

<p style="margin-left:6%;">Blacklist entries provided by
the snort community contain a list of single ip addresses
and <b>snort2pfcd</b> will only accept entries in this
format (e.g. 192.168.0.1). Each entry should be on a
separate line.</p>

<p style="margin-top: 1em" valign="top"><b>NOTES</b></p>

<p style="margin-left:6%;">While <b>snort2pfcd</b> will
parse the default snort alert file, this can produce less
than real-time blocking given the burden being placed on
snort especially over an active, fast or low latency
connection. Would strongly recommend using a spooler like
barnyard2 to output the text alerts from the snort unified2
binary output.</p>

<p style="margin-left:6%; margin-top: 1em">By default, the
user-supplied whitelist is prepended with the addresses of
all of the local interfaces as the handling of these
addresses are usually specified by more complex packet
filter rules and simply blocking these addresses can cause
problems with certain configurations.</p>

<p style="margin-left:6%; margin-top: 1em">The
user-supplied whitelist can also be prepended with the
address of the external interface only for paranoid
configurations. Lo0 is always whitelisted.</p>


<p style="margin-left:6%; margin-top: 1em"><b>snort2pfcd</b>
also automatically whitelists addresses found within the
/etc/resolv.conf file as these addresses should also be
handled by specific packet filter rules.</p>

<p style="margin-left:6%; margin-top: 1em">A static
blacklist table is also maintained and populated within
packet filter with the addresses found within the
/usr/local/etc/snort/rules/iplists/default.blacklist file.
These addresses can be supplied by the user or automatically
populated with addresses supplied by the snort
community.</p>

<p style="margin-top: 1em" valign="top"><b>CREDITS</b></p>

<p style="margin-left:6%;">This program is based on snort2c
written by Antonio Benojar which was based on the original
snort2pf perl script written by Stephan Schmieder.
Expiration of entries use Henrik Gustafsson&rsquo;s
expiretable functions.</p>

<p style="margin-top: 1em" valign="top"><b>SEE ALSO</b></p>

<p style="margin-left:6%;">pf(4), pfctl(8), snort(8),
expiretable(1), libcidr(3),</p>

<p style="margin-top: 1em" valign="top"><b>AUTHORS</b></p>

<p style="margin-left:6%;">Samee Shahzada
&lt;onestsam@gmail.com&gt;</p>

<p style="margin-left:6%; margin-top: 1em">May&nbsp;8,
2017</p>
<hr>
</body>
</html>
