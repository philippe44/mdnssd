#ifndef __MDNSSD_ITF_H
#define __MDNSSD_ITF_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
#include <inaddr.h>
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

typedef struct txt_attr_s {
	char *name;
	char *value;
} txt_attr_t;

typedef struct mDNSservice_s {
  struct mDNSservice_s *next;		// must be first
  struct in_addr host;				// the host of the service
  char* name; 						// name from PTR
  char* hostname; 					// from SRV
  struct in_addr addr; 				// from A
  unsigned short port; 				// from SRV;
  unsigned int since;				// seconds since last seen
  bool expired;
  txt_attr_t *attr;
  int attr_count;
} mDNSservice_t;

struct mDNShandle_s;

typedef enum { MDNS_NONE, MDNS_RESET, MDNS_SUSPEND } mDNScontrol_e;

typedef bool mdns_callback_t(mDNSservice_t *services, void *cookie, bool *stop);

bool 					query_mDNS(struct mDNShandle_s *handle, char* query_arg,
								   int ttl, int runtime, mdns_callback_t *callback,
								   void *cookie);
struct mDNShandle_s*	init_mDNS(int dbg, struct in_addr host);
void 					control_mDNS(struct mDNShandle_s *handle, mDNScontrol_e request);
void 					close_mDNS(struct mDNShandle_s *handle);
void 					free_list_mDNS(mDNSservice_t *slist);
mDNSservice_t* 			get_list_mDNS(struct mDNShandle_s *handle);
#endif
