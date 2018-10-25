/*

  mdnssd-min

  mdnssd-min is a minimal DNS-SD and mDNS client that takes a service type
  as its argument and returns the IPv4 and/or IPv6 addreses and port numbers
  running a service of the type.

  License: GPLv3
  Author: juul@sudomesh.org
  Copyright 2013-2014 Marc Juul Christoffersen.

  modifications by: philippe44@outlook.com

  References:

  DNS RFC: http://tools.ietf.org/html/rfc1035
    Section 4.1, 3.2.2 and 3.2.4

  DNS RFC: http://tools.ietf.org/html/rfc1034
	Section 3.7.1

  DNS Security Extensions RFC: http://tools.ietf.org/html/rfc2535
    Section 6.1

  mDNS RFC: http://tools.ietf.org/html/rfc6762
    Section 18.

  DNS-SD RFC: http://tools.ietf.org/html/rfc6763

  DNS SRV RFC: http://tools.ietf.org/html/rfc2782

*/

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>

#include "mdnssd-min.h"

#ifndef _WIN32
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#if defined(linux) || defined(__APPLE__) || defined(__FreeBSD__)
#include <sys/time.h>
#endif

// is debug mode enabled?
static int debug_mode;

/*---------------------------------------------------------------------------*/
static int debug(const char* format, ...) {
  va_list args;
  int ret;

  if(!debug_mode) {
	return 0;
  }
  va_start(args, format);
  ret = vfprintf(stderr, format, args);

  va_end(args);
  return ret;
}


/*---------------------------------------------------------------------------*/
static uint32_t gettime(void) {
#ifdef _WIN32
	return GetTickCount() / 1000;
#else
#if defined(linux) || defined(__FreeBSD__)
	struct timespec ts;
	if (!clock_gettime(CLOCK_MONOTONIC, &ts)) {
		return ts.tv_sec;
	}
#endif
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return tv.tv_sec;
#endif
}


/*---------------------------------------------------------------------------*/
static item_t *insert_item(item_t *item, item_t **list) {
  if (*list) item->next = *list;
  else item->next = NULL;

  *list = item;

  return item;
}


/*---------------------------------------------------------------------------*/
/*
static item_t *insert_tail_item(item_t *item, item_t **list) {
  if (*list) {
	struct item_s *p = *list;
	while (p->next) p = p->next;
	item->next = p->next;
	p->next = item;
  } else {
	item->next = NULL;
	*list = item;
  }

  return item;
}
*/


/*---------------------------------------------------------------------------*/
/*
static item_t *insert_ordered_item(item_t *item, item_t **list, int (*compare)(void *a, void *b)) {
  if (*list) {
	struct item_s *p = *list;
	while (p->next && compare(p->next, item) <= 0) p = p->next;
	item->next = p->next;
	p->next = item;
  } else {
	item->next = NULL;
	*list = item;
  }

  return item;
}
*/

/*---------------------------------------------------------------------------*/
static item_t *remove_item(item_t *item, item_t **list) {
  if (item != *list) {
	struct item_s *p = *list;
	while (p && p->next != item) p = p->next;
	if (p) p->next = item->next;
	item->next = NULL;
  } else *list = (*list)->next;

  return item;
}

/*---------------------------------------------------------------------------*/
static void clear_list(item_t *list, void (*free_func)(void *)) {
  if (!list) return;
  while (list) {
	struct item_s *next = list->next;
	if (free_func) (*free_func)(list);
	else free(list);
	list = next;
  }
}


/*---------------------------------------------------------------------------*/
static void free_a(alist_t* a) {
	if (a->name) free(a->name);
	free(a);
}


/*---------------------------------------------------------------------------*/
static void free_s(slist_t* s) {
	if (s->name) free(s->name);
	if (s->hostname) free(s->hostname);
	if (s->txt) free(s->txt);
	free(s);
}


/*---------------------------------------------------------------------------*/
static char* prepare_query_string(char* name) {
  int i;
  int count;
  int lastdot = 0;
  int len = strlen(name);
  char* result;

  result = malloc(len + 2);
  if(!result) {
	debug("failed to allocate memory for parsed hostname");
	return NULL;
  }

  count = 0;
  for(i=0; i < len+1; i++) {
	if((name[i] == '.') || (name[i] == '\0')) {
	  result[lastdot] = (char) count;
	  count = 0;
	  lastdot = i+1;
	  continue;
	}
	result[i+1] = name[i];
	count++;
  }
  result[len+1] = '\0';

  return result;
}


// expects host byte_order
/*---------------------------------------------------------------------------*/
static mDNSFlags* mdns_parse_header_flags(uint16_t data) {
  mDNSFlags* flags = malloc(sizeof(mDNSFlags));

  if(!flags) {
	debug("could not allocate memory for parsing header flags");
	return NULL;
  }

  flags->rcode = data & 0xf;
  flags->cd = (data >> 4) & 1;
  flags->ad = (data >> 5) & 1;
  flags->zero = (data >> 6) & 1;
  flags->ra = (data >> 7) & 1;
  flags->rd = (data >> 8) & 1;
  flags->tc = (data >> 9) & 1;
  flags->aa = (data >> 10) & 1;
  flags->opcode = (data >> 14) & 0xf;
  flags->qr = (data >> 15) & 1;

  return flags;
}


// outputs host byte order
/*---------------------------------------------------------------------------*/
static uint16_t mdns_pack_header_flags(mDNSFlags flags) {
  uint16_t packed = 0;

  packed |= (flags.rcode & 0xfff0);
  packed |= (flags.cd & 0xfffe) << 4;
  packed |= (flags.ad & 0xfffe) << 5;
  packed |= (flags.zero & 0xfffe) << 6;
  packed |= (flags.ra & 0xfffe) << 7;
  packed |= (flags.rd & 0xfffe) << 8;
  packed |= (flags.tc & 0xfffe) << 9;
  packed |= (flags.aa & 0xfffe) << 10;
  packed |= (flags.opcode & 0xfff0) << 14;
  packed |= (flags.qr & 0xfffe) << 15;

  return packed;
}


/*---------------------------------------------------------------------------*/
static char* mdns_pack_question(mDNSQuestion* q, size_t* size) {
  char* packed;
  size_t name_length;
  uint16_t qtype;
  uint16_t qclass;


  name_length = strlen(q->qname) + 1;
  if(name_length > DNS_MAX_HOSTNAME_LENGTH) {
	debug("domain name too long");
	return NULL;
  }

  debug("name length: %u\n", name_length);

  *size = name_length + 2 + 2;

  // 1 char for terminating \0, 2 for qtype and 2 for qclass
  packed = malloc(*size);
  if(!packed) {
	debug("could not allocate memory for DNS question");
	return NULL;
  }

  memcpy(packed, q->qname, name_length);

  // The top bit of the qclass field is repurposed by mDNS
  // to indicate that a unicast response is preferred
  // See RFC 6762 section 5.4
  if(q->prefer_unicast_response) {
	q->qclass |= 1 << 15;
  }

  qtype = htons(q->qtype);
  qclass = htons(q->qclass);

  memcpy(packed + name_length, &qtype, 2);
  memcpy(packed + name_length + 2, &qclass, 2);

  return packed;
}


// parse question section
/*---------------------------------------------------------------------------*/
static int mdns_parse_question(char* message, char* data, int size) {
  mDNSQuestion q;
  char* cur;
  int parsed = 0;

  cur = data;
  // TODO check for invalid length
  q.qname = parse_rr_name(message, data, &parsed);
  free(q.qname);
  cur += parsed;
  if(parsed > size) {
	debug("qname is too long");
	return 0;
  }

  memcpy(&(q.qtype), cur, 2);
  q.qtype = ntohs(q.qtype);
  cur += 2;
  parsed += 2;
  if(parsed > size) {
	return 0;
  }

  memcpy(&(q.qclass), cur, 2);
  q.qclass = ntohs(q.qclass);
  cur += 2;
  parsed += 2;
  if(parsed > size) {
	return 0;
  }

  return parsed;
}


/*---------------------------------------------------------------------------*/
static void mdns_message_print(mDNSMessage* msg) {

  mDNSFlags* flags = mdns_parse_header_flags(msg->flags);

  if (!flags) return;
/*
  debug("ID: %u\n", msg->id);
  debug("Flags: \n");
  debug("      QR: %u\n", flags->qr);
  debug("  OPCODE: %u\n", flags->opcode);
  debug("      AA: %u\n", flags->aa);
  debug("      TC: %u\n", flags->tc);
  debug("      RD: %u\n", flags->rd);
  debug("      RA: %u\n", flags->ra);
  debug("       Z: %u\n", flags->zero);
  debug("      AD: %u\n", flags->ad);
  debug("      CD: %u\n", flags->cd);
  debug("   RCODE: %u\n", flags->rcode);
  debug("\n");
  debug("QDCOUNT: %u\n", msg->qd_count);
  debug("ANCOUNT: %u\n", msg->an_count);
  debug("NSCOUNT: %u\n", msg->ns_count);
  debug("ARCOUNT: %u\n", msg->ar_count);
  debug("Resource records:\n");
*/
  free(flags);
}


// parse A resource record
/*---------------------------------------------------------------------------*/
static int mdns_parse_rr_a(char* data, struct in_addr *addr) {
  addr->s_addr = INADDR_ANY;
  // ignore local link responses
  if ((data[0] == '\xa9') && (data[1] == '\xfe')) return 4;

  memcpy(&(addr->s_addr), data, 4);

  debug("        A: %s\n", inet_ntoa(*addr));

  return 4;
}


// parse PTR resource record
/*---------------------------------------------------------------------------*/
static int mdns_parse_rr_ptr(char* message, char* data, char **name) {
  int parsed = 0;

  *name = parse_rr_name(message, data, &parsed);

  debug("        PTR: %s\n", *name);

  return parsed;
}


// parse SRV resource record
/*---------------------------------------------------------------------------*/
static int mdns_parse_rr_srv(char* message, char* data, char **hostname, unsigned short *port) {
  uint16_t priority;
  uint16_t weight;
  int parsed = 0;

  // TODO currently we do nothing with the priority and weight
  memcpy(&priority, data, 2);
  priority = ntohs(priority);
  data += 2;
  parsed += 2;

  memcpy(&weight, data, 2);
  weight = ntohs(weight);
  data += 2;
  parsed += 2;

  memcpy(port, data, 2);
  *port = ntohs(*port);
  data += 2;
  parsed += 2;

  *hostname = parse_rr_name(message, data, &parsed);

  debug("        SRV target: %s\n", *hostname);
  debug("        SRV port: %u\n", *port);

  return parsed;
}


// parse TXT resource record
/*---------------------------------------------------------------------------*/
static void mdns_parse_rr_txt(char* message, mDNSResourceRecord* rr, char**txt, int *length) {
  if ((*txt = malloc(rr->rdata_length)) != NULL) {
	memcpy(*txt, rr->rdata, rr->rdata_length);
	*length = rr->rdata_length;
  }
}


// get name compression offset
/*---------------------------------------------------------------------------*/
static uint16_t get_offset(char* data) {
  uint16_t offset;

  memcpy(&offset, data, 2);
  offset = ntohs(offset);

  if((offset >> 14) & 3) {
	// this means that the name is a reference to
	// a string instead of a string
	offset &= 0x3fff; // change two most significant bits to 0
	return offset;
  }
  return 0;

};


// parse a domain name
// of the type included in resource records
/*---------------------------------------------------------------------------*/
static char* parse_rr_name(char* message, char* name, int* parsed) {

  int dereference_count = 0;
  uint16_t offset;
  int label_len;
  char* out;
  int out_i = 0;
  int i = 0;
  int did_jump = 0;
  int pars = 0;

  out = malloc(MAX_RR_NAME_SIZE);
  if(!out) {
	debug("could not allocate memory for resource record name");
	return NULL;
  }

  while(1) {
	offset = get_offset(name);
	if(offset) {
	  if(!did_jump) {
		pars += 2; // parsed two bytes before jump
	  }
	  did_jump = 1;
	  name = message + offset;
	  dereference_count++;
	  if(dereference_count >= MAX_DEREFERENCE_COUNT) {
		// don't allow messages to crash this app
		free(out);
		return NULL;
	  }
	  continue;
	}
	// insert a dot between labels
	if(out_i > 0) {
	  out[out_i++] = '.';

	  if(out_i+1 >= MAX_RR_NAME_SIZE) {
		free(out);
		return NULL;
	  }
	}
	// it wasn't an offset, so it must be a string length
	label_len = (int) name[0];
	name++;
	if(!did_jump) {
	  pars++;
	}
	for(i=0; i < label_len; i++) {
	  out[out_i++] = name[i];
	  if(out_i+1 >= MAX_RR_NAME_SIZE) {
		free(out);
		return NULL;
	  }
	  if(!did_jump) {
		pars++;
	  }
	}
	name += label_len;
	if(name[0] == '\0') {
	  out[out_i] = '\0';
	  if(!did_jump) {
		pars++;
	  }
	  *parsed += pars;
	  return out;
	}
  }
}


/*---------------------------------------------------------------------------*/
static void free_resource_record(mDNSResourceRecord* rr) {
  if(rr->name) {
	free(rr->name);
	rr->name = NULL;
  }
}


// parse a resource record
// the answer, authority and additional sections all use the resource record format
/*---------------------------------------------------------------------------*/
static int mdns_parse_rr(struct in_addr host, struct context_s *context, char* message, char* rrdata, int size, int is_answer) {
  mDNSResourceRecord rr;
  int parsed = 0;
  char* cur = rrdata;

  rr.name = NULL;

  rr.name = parse_rr_name(message, rrdata, &parsed);
  if(!rr.name) {
	// TODO are calling functions dealing with this correctly?
	free_resource_record(&rr);
	debug("parsing resource record name failed\n");
	return 0;
  }

  cur += parsed;

  // +10 because type, class, ttl and rdata_lenth
  // take up total 10 bytes
  if(parsed+10 > size) {
	free_resource_record(&rr);
	return 0;
  }

  debug("      Resource Record Name: %s\n", rr.name);

  memcpy(&(rr.type), cur, 2);
  rr.type = ntohs(rr.type);
  cur += 2;
  parsed += 2;

  debug("      Resource Record Type: %u\n", rr.type);

  memcpy(&(rr.class), cur, 2);
  rr.class = ntohs(rr.class);
  cur += 2;
  parsed += 2;

  memcpy(&(rr.ttl), cur, 4);
  rr.ttl = ntohl(rr.ttl);
  cur += 4;
  parsed += 4;

  debug("      ttl: %u\n", rr.ttl);

  memcpy(&(rr.rdata_length), cur, 2);
  rr.rdata_length = ntohs(rr.rdata_length);
  cur += 2;
  parsed += 2;

  if(parsed > size) {
	free_resource_record(&rr);
	return 0;
  }

  rr.rdata = cur;
  parsed += rr.rdata_length;

  if (is_answer) {
	if (rr.type == DNS_RR_TYPE_A) store_a(context, &rr);
	else store_other(host, context, message, &rr);
  }

  free_resource_record(&rr);

  debug("    ------------------------------\n");

  return parsed;
}


// TODO this only parses the header so far
/*---------------------------------------------------------------------------*/
static int mdns_parse_message_net(struct in_addr host, struct context_s *context, char* data, int size, mDNSMessage* msg) {

  int parsed = 0;
  int i;

  if(size < DNS_HEADER_SIZE) {
	return 0;
  }

  memcpy(msg, data, DNS_HEADER_SIZE);
  msg->id = ntohs(msg->id);
  msg->flags = ntohs(msg->flags);
  msg->qd_count = ntohs(msg->qd_count);
  msg->an_count = ntohs(msg->an_count);
  msg->ns_count = ntohs(msg->ns_count);
  msg->ar_count = ntohs(msg->ar_count);
  parsed += DNS_HEADER_SIZE;

  mdns_message_print(msg);

  debug("  Question records [%u] (not shown)\n", msg->qd_count);
  for(i=0; i < msg->qd_count; i++) {
	parsed += mdns_parse_question(data, data+parsed, size-parsed);
  }

  debug("  Answer records [%u]\n", msg->an_count);
  for(i=0; i < msg->an_count; i++) {
	//debug("    Answer record %u of %u\n", i+1, msg->an_count);
	parsed += mdns_parse_rr(host, context, data, data+parsed, size-parsed, 1);
  }

  debug("  Nameserver records [%u] (not shown)\n", msg->ns_count);
  for(i=0; i < msg->ns_count; i++) {
	parsed += mdns_parse_rr(host, context, data, data+parsed, size-parsed, 0);
  }

  debug("  Additional records [%u] (not shown)\n", msg->ns_count);
  for(i=0; i < msg->ar_count; i++) {
	parsed += mdns_parse_rr(host, context, data, data+parsed, size-parsed, 1);
  }

  return parsed;
}


/*---------------------------------------------------------------------------*/
static mDNSMessage* mdns_build_query_message(char* query_str, uint16_t query_type) {
  mDNSMessage* msg;
  mDNSQuestion question;
  mDNSFlags flags;

  msg = malloc(sizeof(mDNSMessage));

  if(!msg) {
	debug("failed to allocate memory for mDNS message");
	return NULL;
  }

  flags.qr = 0; // this is a query
  flags.opcode = 0; // opcode must be 0 for multicast
  flags.aa = 0; // must be 0 for queries
  flags.tc = 0; // no (more) known-answer records coming
  flags.rd = 0; // must be 0 for multicast
  flags.ra = 0; // must be 0 for multicast
  flags.zero = 0; // must be zero
  flags.ad = 0; // must be zero for multicast
  flags.cd = 0; // must be zero for multicast
  flags.rcode = 0;

  msg->id = 0; // should be 0 for multicast query messages
  msg->flags = htons(mdns_pack_header_flags(flags));
  msg->qd_count = htons(1); // one question
  msg->an_count =  msg->ns_count =  msg->ar_count = 0;

  question.qname = query_str;

  if(!question.qname) {
	return NULL;
  }

  question.prefer_unicast_response = 0;
  question.qtype = query_type;
  question.qclass = 1; // class for the internet (RFC 1035 section 3.2.4)

  if ((msg->data = mdns_pack_question(&question, &(msg->data_size))) == NULL) {
	  free(msg);
	  return NULL;
  }

  return msg;
}

/*---------------------------------------------------------------------------*/
static char* mdns_pack_message(mDNSMessage* msg, size_t* pack_length) {
  char* pack;

  *pack_length = DNS_HEADER_SIZE + msg->data_size;
  if(*pack_length > DNS_MESSAGE_MAX_SIZE) {
	debug("mDNS message too large");
	return NULL;
  }

  pack = malloc(*pack_length);
  if(!pack) {
	debug("failed to allocate data for packed mDNS message");
	return NULL;
  }

  memcpy(pack, msg, DNS_HEADER_SIZE);
  memcpy(pack + DNS_HEADER_SIZE, msg->data, msg->data_size);

  return pack;
}


// parse TXT resource record
/*---------------------------------------------------------------------------*/
static void mdns_parse_txt(char *txt, int txt_length, mDNSservice_t *s) {
	int len = 0, count = 0;
	char *p;
	int i;

	if (!txt) return;

	while (len + count < txt_length) {
		len += * ((char*) txt + len + count);
		count++;
	}

	s->attr_count = count;
	s->attr = malloc(count * sizeof(txt_attr_t));

	p = txt;
	for (i = 0; i < count; i++) {
		char *value = memchr(p + 1, '=', *p);
		if (value) {
			len = *p - (value - (p + 1)) - 1;
			s->attr[i].value = malloc(len + 1);
			memcpy(s->attr[i].value, value + 1, len);
			s->attr[i].value[len] = '\0';
			len = (value - (p + 1));
			s->attr[i].name = malloc(len + 1);
			memcpy(s->attr[i].name, p + 1, len);
			s->attr[i].name[len] = '\0';
		}
		else {
			len = *p;
			s->attr[i].name = malloc(len + 1);
			memcpy(s->attr[i].name, p + 1, len);
			s->attr[i].name[len] = '\0';
			s->attr[i].value = NULL;
		}
		p += *p + 1;
	}
}


/*---------------------------------------------------------------------------*/
static int send_query(int sock, char* query_arg, uint16_t query_type) {

  mDNSMessage* msg;
  char* data;
  size_t data_size;
  int res;
  struct sockaddr_in addr;
  socklen_t addrlen;
  char* query_str;

  if ((query_str = prepare_query_string(query_arg)) == NULL) return -1;

  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);

  // build and pack the query message
  msg = mdns_build_query_message(query_str, query_type);
  free(query_str);
  if (!msg) return -1;

  data = mdns_pack_message(msg, &data_size);
  free(msg->data);
  free(msg);
  if (!data) return -1;

  debug("Sending DNS message with length: %u\n", data_size);
  // send query message
  res = sendto(sock, data, data_size, 0, (struct sockaddr *) &addr, addrlen);
  free(data);

  return res;
}


/*
  An answer is complete if it has all of:
	* A hostname (from a SRV record)
	* A port (from a SRV record)
	* An IP address (from an A record)
 */
 /*---------------------------------------------------------------------------*/
static int is_complete(slist_t *s) {
  if (s->addr.s_addr && s->hostname && s->port && s->txt) return 1;
  else return 0;
}

/*---------------------------------------------------------------------------*/
static void store_a(struct context_s *context, mDNSResourceRecord* rr) {
  alist_t *b;
  struct in_addr addr;

  mdns_parse_rr_a(rr->rdata, &addr);

  for (b = context->alist; b; b = b->next) {

	if (!strcmp(b->name, rr->name)) {
		if (addr.s_addr) b->addr = addr;
		b->eol = gettime() + rr->ttl;
		return;
	}
  }

  b = malloc(sizeof(alist_t));
  b->addr = addr;
  b->name = strdup(rr->name);
  b->eol = gettime() + rr->ttl;

  insert_item((item_t*) b, (item_t**) &context->alist);
}


/*---------------------------------------------------------------------------*/
static slist_t *create_s(struct in_addr host, char *name, slist_t **list) {
  slist_t *s = calloc(1, sizeof(slist_t));
  s->name = strdup(name);
  s->host = host;
  insert_item((item_t*) s, (item_t**) list);
  return s;
}


/*---------------------------------------------------------------------------*/
static void store_other(struct in_addr host, struct context_s *context, char *message, mDNSResourceRecord* rr) {
  slist_t *b = NULL;
  char *name = NULL;
  uint32_t now, ttl;

  // for a PTR, the rr name must match exactly the query, for others it shall
  // at least contain it, otherwise it(s not for us
  if ((rr->type == DNS_RR_TYPE_PTR && strcmp(rr->name, context->query)) ||
	  !strstr(rr->name, context->query)) return;

  now = gettime();
  ttl = (context->ttl && context->ttl < rr->ttl) ? context->ttl : rr->ttl;

  // the queuing tool is head insertion, so this reverts the time or arrival
  // entry with ttl = 0 are not created, deletion must apply to an existing one
  switch (rr->type) {

	// PTR: get service name
	case DNS_RR_TYPE_PTR: {
	  mdns_parse_rr_ptr(message, rr->rdata, &name);

	  // can't factorize the "for/switch" as name is update above
	  for (b = context->slist; b && (strcmp(b->name, name) || b->host.s_addr != host.s_addr); b = b->next);
	  if (!b && rr->ttl) b = create_s(host, name, &context->slist);

	  if (b) b->eol[0] = now + ttl;

	  free(name);
	  break;
	}

	// SRV: service descriptor ==> get hostname & port
	case DNS_RR_TYPE_SRV: {
	  unsigned short port;
	  char *hostname = NULL;

	  mdns_parse_rr_srv(message, rr->rdata, &hostname, &port);

	  for (b = context->slist; b && (strcmp(b->name, rr->name) || b->host.s_addr != host.s_addr); b = b->next);
	  if (!b && rr->ttl) b = create_s(host, rr->name, &context->slist);

	  if (b) {
		// update port
		if (port && b->port != port) {
		  b->port = port;
		  b->status = MDNS_UPDATED;
		}
		// update hostname
		if (!b->hostname || strcmp(b->hostname, hostname)) {
		  NFREE(b->hostname);
		  b->status = MDNS_UPDATED;
		  b->hostname = strdup(hostname);
		}
		b->eol[1] = now + ttl;
	  }

	  free(hostname);
	  break;
	}

	// TXT: get txt content
	case DNS_RR_TYPE_TXT: {
	  char *txt = NULL;
	  int length = 0;

	  mdns_parse_rr_txt(message, rr, &txt, &length);

	  for (b = context->slist; b && (strcmp(b->name, rr->name) || b->host.s_addr != host.s_addr); b = b->next);
	  if (!b && rr->ttl) b = create_s(host, rr->name, &context->slist);

	  if (b) {
		// update txt
		if (!b->txt || memcmp(b->txt, txt, length)) {
		  NFREE(b->txt);
		  b->txt = malloc(length);
		  b->txt_length = length;
		  memcpy(b->txt, txt, length);
		  b->status = MDNS_UPDATED;
		}
		b->eol[2] = now + ttl;
	  }

	  free(txt);
	  break;
	}
  }

  // set when was it last seen, except for deletion
  if (b && rr->ttl) b->seen = now;
}


/*---------------------------------------------------------------------------*/
static mDNSservice_t *build_update(struct context_s *context, bool build) {
  mDNSservice_t *services = NULL;
  uint32_t now = gettime();
  alist_t *a;
  slist_t *s;

  // cleanup the alist
  a = context->alist;
  while (a) {
	alist_t *next = a->next;
	if (a->eol - now > 0x7fffffff) {
		remove_item((item_t*) a, (item_t**) &context->alist);
		free_a(a);
	}
	a = next;
  }

  s = context->slist;
  // order of the slist is reverse time of arrival so the order of the services,
  // as it uses the same queueing tool, will revert that back ... or so I think
  while (s) {
	slist_t *next = s->next;
	bool expired;

	// got a complete answer, search for A
	if (s->hostname && s->port && s->txt) {
		for (a = context->alist; a; a = a->next) {
			if (strcmp(s->hostname, a->name)) continue;
			if (s->addr.s_addr != a->addr.s_addr) {
				s->addr.s_addr = a->addr.s_addr;
				s->status = MDNS_UPDATED;
			}
			break;
		}
	}

	expired = s->eol[0] - now > 0x7fffffff || s->eol[1] - now > 0x7fffffff || s->eol[2] - now > 0x7fffffff;

	// a service has expired - must be done before the below check to make sure
	// that the expiry is after in the queue
	if (expired) {
		// set IP & port to zero so that caller knows, but txt is needed
		if (build && is_complete(s)) {
			mDNSservice_t *p = malloc(sizeof(mDNSservice_t));
			p->host = s->host;
			p->name = strdup(s->name);
			p->hostname = strdup(s->hostname);
			p->addr = s->addr;
			p->port = s->port;
			p->since = now - s->seen;
			p->expired = true;
			mdns_parse_txt(s->txt, s->txt_length, p);
			insert_item((item_t*) p, (item_t**) &services);
		}
	}

	// a service has been updated, but it might have expired just after - so we
	// will have both creation & destruction in the response with correct order
	if (build && is_complete(s) && s->status != MDNS_CURRENT) {
		mDNSservice_t *p = malloc(sizeof(mDNSservice_t));
		p->host = s->host;
		p->name = strdup(s->name);
		p->hostname = strdup(s->hostname);
		p->addr = s->addr;
		p->port = s->port;
		p->since = now - s->seen;
		p->expired = false;
		mdns_parse_txt(s->txt, s->txt_length, p);
		insert_item((item_t*)p, (item_t**) &services);
		s->status = MDNS_CURRENT;
	}

	// now we can remove the service
	if (expired) {
		remove_item((item_t*) s, (item_t**) &context->slist);
		free_s(s);
	}

	s = next;
  }

  return services;
}


/*---------------------------------------------------------------------------*/
struct mDNShandle_s *init_mDNS(int dbg, struct in_addr host) {
  int sock;
  int res;
  struct ip_mreq mreq;
  struct sockaddr_in addr;
  socklen_t addrlen;
  int enable = 1;
  char param;
  mDNShandle_t *handle;

  debug_mode = dbg;
  debug("Opening socket\n");
  sock = socket(AF_INET, SOCK_DGRAM, 0);
  if(sock < 0) {
	debug("error opening socket");
	return NULL;
  }

  param = 32;
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, (void*) &param, sizeof(param)) < 0) {
	printf("error setting multicast TTL");
	return NULL;
  }

  if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &enable, sizeof(enable)) < 0) {
	debug("error setting reuseaddr");
	return NULL;
  }

  param = 1;
  if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, (void*) &param, sizeof(param)) < 0) {
	debug("error seeting multicast_loop");
	return NULL;
  }

#if !defined(WIN32)
  if (!getsockopt(sock, SOL_SOCKET, SO_REUSEPORT,(void*) &enable, &addrlen)) {
	enable = 1;
	if (setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,(void*) &enable, sizeof(enable)) < 0) {
	  debug("error setting reuseport");
	}
  }
#endif

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = INADDR_ANY;
  addrlen = sizeof(addr);

  res = bind(sock, (struct sockaddr *) &addr, addrlen);
  if (res < 0) {
	debug("error binding socket");
	return NULL;
  }

  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  mreq.imr_interface.s_addr = host.s_addr;

  if (setsockopt (sock, IPPROTO_IP, IP_MULTICAST_IF, (void*) &mreq.imr_interface.s_addr, sizeof(mreq.imr_interface.s_addr)) < 0)  {
	debug("bound to if failed");
	return NULL;
  }

  debug("Setting socket options for multicast\n");
  if(setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*) &mreq, sizeof(mreq)) < 0) {
	debug("setsockopt failed");
	return NULL;
  }

  handle = malloc(sizeof(mDNShandle_t));
  handle->sock = sock;
  handle->state = MDNS_IDLE;
  handle->last = gettime() - 3600;;
  handle->context.alist = NULL;
  handle->context.slist = NULL;

  return handle;
}


/*---------------------------------------------------------------------------*/
void control_mDNS(struct mDNShandle_s *handle, mDNScontrol_e request) {
	if (!handle) return;
	// reset useless when stopped and is taken care by the query if running
	if (handle->state == MDNS_RUNNING) handle->control = request;
	else if (request == MDNS_RESET) clear_context(&handle->context);
}


/*---------------------------------------------------------------------------*/
void close_mDNS(struct mDNShandle_s *handle) {
	if (!handle) return;
	// query is not running, clear here, otherwise the query will self-clear
	if (handle->state == MDNS_IDLE) {
		clear_context(&handle->context);
		closesocket(handle->sock);
		handle->sock = -1;
		free(handle);
	} else handle->state = MDNS_IDLE;
}


/*---------------------------------------------------------------------------*/
static void clear_context(struct context_s *context) {
  clear_list((void*) context->alist, (void (*)(void*)) &free_a);
  clear_list((void*) context->slist, (void (*)(void*)) &free_s);
  context->slist = NULL;
  context->alist = NULL;
}


/*---------------------------------------------------------------------------*/
static void free_item_mDNS(mDNSservice_t* slist) {
	int i;

	free(slist->name);
	free(slist->hostname);

	for (i = 0; i < slist->attr_count; i++) {
		if (slist->attr[i].name) free(slist->attr[i].name);
		if (slist->attr[i].value) free(slist->attr[i].value);
	}

	free(slist->attr);

	free(slist);
}


/*---------------------------------------------------------------------------*/
void free_list_mDNS(mDNSservice_t* slist) {
  clear_list((void*) slist, (void(*)(void*)) &free_item_mDNS);
}


/*---------------------------------------------------------------------------*/
mDNSservice_t* get_list_mDNS(struct mDNShandle_s *handle) {
  slist_t *s;
  mDNSservice_t *services = NULL, *p;

  for (s = handle->context.slist; s; s = s->next) {
	if (is_complete(s)) {
		p = malloc(sizeof(mDNSservice_t));
		p->name = strdup(s->name);
		p->hostname = strdup(s->hostname);
		p->addr = s->addr;
		p->port = s->port;
		p->expired = false;
		mdns_parse_txt(s->txt, s->txt_length, p);
		insert_item((item_t*) s, (item_t**) &services);
	}
  }

  return services;
}


/*---------------------------------------------------------------------------*/
bool query_mDNS(struct mDNShandle_s *handle, char* query, int ttl, int runtime, mdns_callback_t *callback, void *cookie) {
  struct sockaddr_in addr;
  socklen_t addrlen;
  int res, parsed;
  char* recvdata;
  fd_set active_fd_set, read_fd_set, except_fd_set;
  mDNSservice_t *slist;
  uint32_t now;
  bool stop = false, rc = true;

  if (!handle || handle->sock < 0) return false;

  if(query[0] != '_') {
	debug("only service queries currently supported");
	return false;;
  }

  if (runtime) runtime += gettime();

  addr.sin_family = AF_INET;
  addr.sin_port = htons(MDNS_PORT);
  addr.sin_addr.s_addr = inet_addr(MDNS_MULTICAST_ADDRESS);
  addrlen = sizeof(addr);

  recvdata = malloc(DNS_BUFFER_SIZE);
  if (!recvdata) return false;

  FD_ZERO(&active_fd_set);
  FD_SET(handle->sock, &active_fd_set);

  debug("Entering main loop\n");

  handle->context.query = query;
  handle->context.ttl = ttl;
  handle->state = MDNS_RUNNING;

  // this protects against a u32 rollover
  while (1) {
	struct timeval sel_time = {0, 50*1000};

	now = gettime();

	// re-launch a search regularly
	if (handle->last + 20 - now > 0x7fffffff) {
		send_query(handle->sock, handle->context.query, DNS_RR_TYPE_PTR);
		handle->last = now;
	}

	read_fd_set = active_fd_set;
	except_fd_set = active_fd_set;

	res = select(handle->sock + 1, &read_fd_set, NULL, &except_fd_set, &sel_time);

	// finishing or suspending query
	if (handle->state == MDNS_IDLE || handle->control == MDNS_SUSPEND || (runtime && now > runtime)) break;

	// just clear list
	if (handle->control == MDNS_RESET) {
	  clear_context(&handle->context);
	  handle->control = MDNS_NONE;
	  handle->last = now - 3600;
	}

	if (res < 0) {
	  rc = false;
	  debug("Select error\n");
	  break;
	}

	if (res == 0) continue;

	if(FD_ISSET(handle->sock, &except_fd_set)) {
	  rc = false;
	  debug("exception on socket");
	  break;
	}

	// DNS messages should arrive as single packets
	// so we don't need to worry about partial receives
	debug("Receiving data\n");
	res = recvfrom(handle->sock, recvdata, DNS_BUFFER_SIZE, 0, (struct sockaddr *) &addr, &addrlen);

	if (res < 0) {
	  rc = false;
	  debug("error receiving");
	  break;
	} else if (res == 0) {
	  rc = false;
	  debug("unknown error"); // TODO for TCP means connection closed, but for UDP?
	}

	debug("Received %u bytes from %s\n", res, inet_ntoa(addr.sin_addr));

	parsed = 0;
	debug("Attempting to parse received data\n");

	// loop through received data
	do {
	  int resp;
	  mDNSMessage msg;

	  resp = mdns_parse_message_net(addr.sin_addr, &handle->context, recvdata+parsed, res, &msg);

	  // if nothing else is parsable, stop parsing
	  if (resp <= 0) break;

	  parsed += resp;
	  debug("--Parsed %u bytes of %u received bytes\n", parsed, res);
	} while(parsed < res); // while there is still something to parse

	debug("Finished parsing received data\n");

	slist = build_update(&handle->context, callback != NULL);
	if (slist && callback && !(*callback)(slist, cookie, &stop)) free_list_mDNS(slist);

	if (stop) break;
  }

  free(recvdata);

  // this is request for stop, we have to clean by ourselves
  if (handle->state == MDNS_IDLE) {
	  clear_context(&handle->context);
	  closesocket(handle->sock);
	  handle->sock = -1;
	  free(handle);
  }

  handle->control = MDNS_NONE;
  handle->state = MDNS_IDLE;

  return rc;
}



