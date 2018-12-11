#################################################################
#	I'm a Simple DNSBL lookup script for IPv4
#
#	Execute me as:
#		python rbl_chk_script.py [ip/cidr]
#	eg:-
#		python rbl_chk_script.py 123.234.123.123/24
#	For just one IP use /32 or you may breakdown the lookup function
#
# 	I might take sometime to looup so sit back an relax :)  - (Could speed up with threads)
#
#################################################################

import ipaddress
import socket
import sys

# Some common blacklists
bl = ['ubl.unsubscore.com','dyna.spamrats.com','dnsbl-3.uceprotect.net','dnsbl-1.uceprotect.net','rf.senderbase.org','spam.dnsbl.sorbs.net','bl.spameatingmonkey.net','bl.spamcannibal.org','socks.dnsbl.sorbs.net','spam.spamrats.com','smtp.dnsbl.sorbs.net','ips.backscatterer.org','bl.blocklist.de','zen.spamhaus.org','rbl.interserver.net','rbl.abuse.ro','dnsbl-2.uceprotect.net','cncdl.anti-spam.org','dnsbl.dronebl.org','query.senderbase.org','sa.senderbase.org','cbl.anti-spam.org','b.barracudacentral.org','spam.dnsbl.anonmails.de','web.dnsbl.sorbs.net','pbl.spamhaus.org','bl.spamcop.net','http.dnsbl.sorbs.net','dnsbl-0.uceprotect.net','dnsbl.sorbs.net','csi.cloudmark.com','zombie.dnsbl.sorbs.net','noptr.spamrats.com','xbl.spamhaus.org','bl.score.senderscore.com','bl.mailspike.net','sbl.spamhaus.org','misc.dnsbl.sorbs.net','dul.dnsbl.sorbs.net','cbl.abuseat.org','multi.surbl.org']

# Lookup script for a given IP
def lookup(ip):
	ip_rev = '.'.join(str(ip).split('.')[::-1])
	listed = 0
	l_rbl  = []
	for i in bl:
		try:
			#Lookup  happens here - if gethostbyname fails the ip is not listed
			socket.gethostbyname(ip_rev + '.' + i + '.')  # final dot to avoid localhost lookups in some env
			l_rbl += [i]
			listed+= 1
		except:
			x = 0
	return [str(listed), l_rbl]		

#Execution starts here	
try:
	for ip in ipaddress.IPv4Network(sys.argv[1].strip("'")):	# Extracting IPs from the given network
		check = lookup(ip)
		if(check[0] != '0'):
			print(str(ip) + ' is listed on ' + check[0] + 'blacklists' + "\n\t".join(check[1]))
		else:
			print(str(ip) + ' is clean' )
except Exception as e:
	print('Error :' + str(e))
		
		
		
