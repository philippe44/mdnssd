#ifndef __MDNSSD_ITF_H
#define __MDNSSD_ITF_H

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <io.h>
typedef uint32_t in_addr_t;
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#endif

#define MAX_ANSWERS (256)

typedef struct {
	char *name;
	char *value;
} txt_attr;

typedef struct {
  struct mDNSItem_s {
	char* name; // name from PTR
	char* hostname; // from SRV
	struct in_addr addr; // from A
	unsigned short port; // from SRVFound;
	txt_attr *attr;
	int	attr_count;
  } items[MAX_ANSWERS];
  int count;
} DiscoveredList;

bool 	query_mDNS(int sock, char* query_arg, DiscoveredList* dlist, int runtime);
int 	init_mDNS(int dbg, in_addr_t host);
void 	close_mDNS(int sock);
void 	free_discovered_list(DiscoveredList* dlist);
#endif
