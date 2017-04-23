# snort2pfcd
v1.6

Analyzes snort alert output and blocks ip addresses for a given snort priority using 
pf table entries for a specified period of time. A whitelist is specified to exclude
local and trusted ip address from being blocked. Whitelist entries can be single ip 
addressess or blocks of addresses in CIDR format (255.255.255.255/32). Snort2pfcd also
preloads the community maintained and supplied pulledpork blacklist by default. This program 
is based on snort2c written by Antonio Benojar which was based on the original snort2pf
perl script written by Stephan Schmieder. Expiration of entries use Henrik 
Gustafsson's expiretable functions.

