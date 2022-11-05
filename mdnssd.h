#pragma once

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

typedef struct mdnssd_txt_attr_s {
	char *name;
	char *value;
} mdnssd_txt_attr_t;

typedef struct mdnssd_service_s {
  struct mdnssd_service_s *next;	// must be first
  struct in_addr host;				// the host of the service
  char* name; 						// name from PTR
  char* hostname; 					// from SRV
  struct in_addr addr; 				// from A
  unsigned short port; 				// from SRV;
  unsigned int since;				// seconds since last seen
  bool expired;
  mdnssd_txt_attr_t *attr;
  int attr_count;
} mdnssd_service_t;

struct mdnssd_handle_s;

typedef enum { MDNS_NONE, MDNS_RESET, MDNS_SUSPEND } mdnssd_control_e;

typedef bool mdns_callback_t(mdnssd_service_t *services, void *cookie, bool *stop);

bool 					mdnssd_query(struct mdnssd_handle_s *handle, char* query_arg, bool unicast,
								   int runtime, mdns_callback_t *callback, void *cookie);
struct mdnssd_handle_s*	mdnssd_init(int dbg, struct in_addr host, bool compliant);
void 					mdnssd_control(struct mdnssd_handle_s *handle, mdnssd_control_e request);
void 					mdnssd_close(struct mdnssd_handle_s *handle);
void 					mdnssd_free_list(mdnssd_service_t *slist);
mdnssd_service_t* 		mdnssd_get_list(struct mdnssd_handle_s *handle);
