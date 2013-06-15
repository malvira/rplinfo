#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"

#include "net/uip.h"
#include "net/uip-ds6.h"
#include "net/rpl/rpl.h"

#include "erbium.h"
#include "er-coap-07.h"

#include "rplinfo.h"

/* debug */
#define DEBUG DEBUG_FULL
#include "net/uip-debug.h"

#define MAX_ENTRY_LEN 256

uint16_t 
ipaddr_add(const uip_ipaddr_t *addr, char *buf)
{
  uint16_t a, n;
  int i, f;
  n = 0;
  for(i = 0, f = 0; i < sizeof(uip_ipaddr_t); i += 2) {
    a = (addr->u8[i] << 8) + addr->u8[i + 1];
    if(a == 0 && f >= 0) {
      if(f++ == 0) { 
	n+= sprintf(&buf[n], "::");
      }
    } else {
      if(f > 0) {
	f = -1;
      } else if(i > 0) {
	n+= sprintf(&buf[n], ":");
      }
      n+= sprintf(&buf[n], "%x", a);
    }
  }
  return n;
}

uint16_t create_route_msg(char *buf, uip_ds6_route_t *r)
{
	uint8_t n = 0;
	n += sprintf(&(buf[n]), "{\"dest\":\"");
	n += ipaddr_add(&r->ipaddr, &(buf[n])); 
	n += sprintf(&(buf[n]), "\",\"next\":\"");
	n += ipaddr_add(&r->nexthop, &(buf[n])); 
	n += sprintf(&(buf[n]), "\"}");
	buf[n] = 0;
	PRINTF("buf: %s\n", buf);
	return n;
}

RESOURCE(routes, METHOD_GET, "rplinfo/routes", "title=\"RPL route info\";rt=\"Data\"");

void
routes_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  int32_t strpos = 0;
  uip_ds6_route_t *r;
  volatile uint8_t i;

  size_t len = 0;
  uint8_t index;
  const char *pstr;
  uint8_t count;

  if ((len = REST.get_query_variable(request, "index", &pstr))) {
    index = (uint8_t)atoi(pstr);
    /* seek to the route entry and return it */
    i = 0;
    for(r = uip_ds6_route_list_head(); r != NULL; r = list_item_next(r), i++) {
      if (i == index) {
	break;
      }
    }
    strpos = create_route_msg(buffer, r);

  } else {
    /* index not provided */
    /* count the number of routes and return the total */
    count = 0;
    for(r = uip_ds6_route_list_head(); r != NULL; r = list_item_next(r)) {
      count++;
    }
    strpos += snprintf((char *)buffer, preferred_size, "%d", count);
  }

  *offset = -1;
  
  REST.set_response_payload(response, buffer, strpos);

}


/*  {"eui":"00050c2a8c9d4ea0","pref":"true","etx":124}*/
/* length of an neighbor entry, must be fixed width */
uint16_t create_parent_msg(char *buf, rpl_parent_t *parent, uint8_t preferred)
{
	uint8_t n = 0;

	n += sprintf(&(buf[n]), "{\"eui\":\"%04x%04x%04x%04x\",", 
		     UIP_HTONS(parent->addr.u16[4]),
		     UIP_HTONS(parent->addr.u16[5]),
		     UIP_HTONS(parent->addr.u16[6]),
		     UIP_HTONS(parent->addr.u16[7]));
	n += sprintf(&(buf[n]), "\"pref\":");
	if(preferred == 1) {
		n += sprintf(&(buf[n]), "true,");
	} else {
		n += sprintf(&(buf[n]), "false,");
	}
	n += sprintf(&(buf[n]), "\"etx\":%d}", parent->mc.obj.etx);

	buf[n] = 0;
	PRINTF("buf: %s\n", buf);
	return n;
}

RESOURCE(parents, METHOD_GET, "rplinfo/parents", "title=\"RPL parent info\";rt=\"Data\"");

static volatile uint8_t cur_neigh_entry;
static volatile uint8_t entry_char_skip;

void
parents_handler(void* request, void* response, uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  int32_t strpos = 0;
  rpl_dag_t *dag;
  rpl_parent_t *parent;
  const char *neighbor_header = "{\"parents\":[";
  const char *neighbor_footer = "]}";
  volatile uint8_t i;
  char entry[MAX_ENTRY_LEN];
  uint16_t entry_len;

  PRINTF("pref size %d\n\r", preferred_size);

  if (*offset == 0) {
    /* send header */    
    PRINTF("do header\n\r");
    strpos += snprintf((char *)buffer+strpos, preferred_size-strpos+1, neighbor_header);
    cur_neigh_entry = 0;
    entry_char_skip = 0;
  } 

  PRINTF("offset %d\n\r", *offset);
  PRINTF("cur_neigh_entry %d\n\r", cur_neigh_entry);
  PRINTF("entry_char_skip %d\n\r", entry_char_skip);
  
  dag = rpl_get_any_dag();
  if(dag != NULL) {
    
    /* seek to the current entry */
    for (parent = dag->preferred_parent, i = 0; parent != NULL; parent = parent->next, i++) {
      if ( i == cur_neigh_entry ) {
	break;
      }
    }
    
    /* fill buffer until past preferred size */
    for (; parent != NULL; parent = parent->next) {
      if (parent == dag->preferred_parent) { 
	entry_len = create_parent_msg(entry, parent, 1);
      } else {
	entry_len = create_parent_msg(entry, parent, 0);
      }
//      PRINTF("skipping %d chars\n\r", entry_char_skip);
      strpos += snprintf((char * )buffer+strpos, preferred_size-strpos+1, &(entry[entry_char_skip]));
      if(entry_char_skip != 0) { entry_char_skip = 0; } 
      if(parent->next != NULL) {
	strpos += snprintf((char * )buffer+strpos, preferred_size-strpos+1, ",");
      }
      if (strpos > preferred_size) {
	break;
      }
      cur_neigh_entry++;
    }      
    
    if (strpos > preferred_size)
    {
      entry_char_skip = entry_len - (strpos - preferred_size) + 1;
      strpos = preferred_size;
    } else {
      entry_char_skip = 0;
    }
    
    if (parent == NULL)
    {
      /* Signal end of resource representation. */
      PRINTF("signal end\n\r");
      strpos += snprintf((char *)buffer+strpos, preferred_size-strpos+1, neighbor_footer);
      *offset = -1;
    } else {
      *offset += strpos;
    }      
  }

  /* snprintf() does not adjust return value if truncated by size. */
  if (strpos > preferred_size)
  {
    strpos = preferred_size;
  }
  
  REST.set_response_payload(response, buffer, strpos);

}

void
rplinfo_activate_resources(void) {
  rest_activate_resource(&resource_parents);
  rest_activate_resource(&resource_routes);
}

