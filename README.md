REST interface for RPL state
============================

Provides a set of RESTful resources for the state of RPL in Contiki OS
using the Erbuim engine.

Setup:
------

Add to your Makefile:

    PROJECTDIRS += rplinfo
    PROJECT_SOURCEFILES += rplinfo.c

Then wherever you activate your resources all:

      rplinfo_activate_resources();

Resources:
----------

###/rplinfo/parents

GET returns a JSON of the parents such as:

    {"parents": [
			{ "eui": "05022a0c9c8cd0af", "pref": true,  "etx":0},
			{ "eui": "47ee4d3c00120b00", "pref": false, "etx":128},
			{ "eui": "47ee4d3c00120300", "pref": false, "etx":128},
			{ "eui": "47ee4d3c00120500", "pref": false, "etx":128},
			{ "eui": "47ee4d3c00120700", "pref": false, "etx":12}
		]
    }

Where "parents" is an array of parent entries. "eui" is the EUI64 mac
address of the devices. "pref" marks if this is the preferred
parent. Link metrics follow. Currently, only "etx" is supported. 

"etx" is currently in raw units (read the Contiki code for the
conversion). 

###/rplinfo/routes

GET returns a JSON of the parents such as:

    {"routes": [
    	       	   {"dest":"aaaa::ee47:3c4d:1200:3","next":fe80::ee47:3c4d:1200:3"},
		   {"dest":"aaaa::ee47:3c4d:1200:b","next":fe80::ee47:3c4d:1200:b"},
		   {"dest":"aaaa::ee47:3c4d:1200:5","next":fe80::ee47:3c4d:1200:5"},
		   {"dest":"aaaa::ee47:3c4d:1200:7","next":fe80::ee473c4d:1200:7"}
	       ]
    }

Where dest is the IP address of the destination and next is the IP
address of the next hop.
