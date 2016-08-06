/*
  Usage: mdnssd-min -t <sec> -n <count> <service_type>

  License: GPLv3
  Author: juul@sudomesh.org
  Copyright 2013-2014 Marc Juul Christoffersen.

  modifications by: philippe44@outlook.com
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef _WIN32
#include <winsock2.h>
#include <in6addr.h>
#include <ws2tcpip.h>
typedef uint32_t in_addr_t;
#elif defined (linux) || defined (__FreeBSD__)
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#if defined (__FreeBSD__)
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#endif
#elif defined (__APPLE__)
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#endif

#include "mdnssd-itf.h"

static int debug_mode;

/*---------------------------------------------------------------------------*/
void print_discovered(DiscoveredList *dlist) {
  int i;

  for(i=0; i < dlist->count; i++) {
	int j;
	printf("%s\t%u\t%-25s %s\n", inet_ntoa(dlist->items[i].addr), dlist->items[i].port, dlist->items[i].hostname, dlist->items[i].name);
	if (debug_mode) {
		for (j=0; j < dlist->items[i].attr_count; j++) {
		  printf("\t%s =  %s\n", dlist->items[i].attr[j].name, dlist->items[i].attr[j].value);
		}
	}
  }
}


/*---------------------------------------------------------------------------*/
// search argv for either stand-along
// arguments like -d or arguments with a value
// like -t 5
int get_arg(int argc, char* argv[], char* key, char** val) {
  int i;
  for(i=1; i < argc; i++) {
	if(strcmp(argv[i], key) == 0) {
	  if(val) { // expecting a value
		if(argc < i+2) {
		  continue;
		}
		*val = argv[i+1];
		return 1;
	  } else { // not expecting a value
		return 1;
	  }

	}
  }
  return 0;
}


#if defined(_WIN32)
/*---------------------------------------------------------------------------*/
void winsock_init(void) {
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int WSerr = WSAStartup(wVersionRequested, &wsaData);
	if (WSerr != 0) {
		exit(1);
	}
}


/*---------------------------------------------------------------------------*/
void winsock_close(void) {
	WSACleanup();
}
#endif


/*---------------------------------------------------------------------------*/
#define MAX_INTERFACES 256
#define DEFAULT_INTERFACE 1
#if !defined(WIN32)
#define INVALID_SOCKET (-1)
#endif
static in_addr_t get_localhost(void)
{
#ifdef WIN32
	char buf[INET_ADDRSTRLEN];
	struct hostent *h = NULL;
	struct sockaddr_in LocalAddr;

	memset(&LocalAddr, 0, sizeof(LocalAddr));

	gethostname(buf, INET_ADDRSTRLEN);
	h = gethostbyname(buf);
	if (h != NULL) {
		memcpy(&LocalAddr.sin_addr, h->h_addr_list[0], 4);
		return LocalAddr.sin_addr.s_addr;
	}
	else return INADDR_ANY;
#elif defined (__APPLE__) || defined(__FreeBSD__)
	struct ifaddrs *ifap, *ifa;

	if (getifaddrs(&ifap) != 0) return INADDR_ANY;

	/* cycle through available interfaces */
	for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
		/* Skip loopback, point-to-point and down interfaces,
		 * except don't skip down interfaces
		 * if we're trying to get a list of configurable interfaces. */
		if ((ifa->ifa_flags & IFF_LOOPBACK) ||
			(!( ifa->ifa_flags & IFF_UP))) {
			continue;
		}
		if (ifa->ifa_addr->sa_family == AF_INET) {
			/* We don't want the loopback interface. */
			if (((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr ==
				htonl(INADDR_LOOPBACK)) {
				continue;
			}
			return ((struct sockaddr_in *)(ifa->ifa_addr))->sin_addr.s_addr;
			break;
		}
	}
	freeifaddrs(ifap);

	return INADDR_ANY;
#else
	char szBuffer[MAX_INTERFACES * sizeof (struct ifreq)];
	struct ifconf ifConf;
	struct ifreq ifReq;
	int nResult;
	long unsigned int i;
	int LocalSock;
	struct sockaddr_in LocalAddr;
	int j = 0;

	/* purify */
	memset(&ifConf,  0, sizeof(ifConf));
	memset(&ifReq,   0, sizeof(ifReq));
	memset(szBuffer, 0, sizeof(szBuffer));
	memset(&LocalAddr, 0, sizeof(LocalAddr));

	/* Create an unbound datagram socket to do the SIOCGIFADDR ioctl on.  */
	LocalSock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (LocalSock == INVALID_SOCKET) return false;
	/* Get the interface configuration information... */
	ifConf.ifc_len = (int)sizeof szBuffer;
	ifConf.ifc_ifcu.ifcu_buf = (caddr_t) szBuffer;
	nResult = ioctl(LocalSock, SIOCGIFCONF, &ifConf);
	if (nResult < 0) {
		close(LocalSock);
		return INADDR_ANY;
	}

	/* Cycle through the list of interfaces looking for IP addresses. */
	for (i = 0lu; i < (long unsigned int)ifConf.ifc_len && j < DEFAULT_INTERFACE; ) {
		struct ifreq *pifReq =
			(struct ifreq *)((caddr_t)ifConf.ifc_req + i);
		i += sizeof *pifReq;
		/* See if this is the sort of interface we want to deal with. */
		memset(ifReq.ifr_name, 0, sizeof(ifReq.ifr_name));
		strncpy(ifReq.ifr_name, pifReq->ifr_name,
			sizeof(ifReq.ifr_name) - 1);
		/* Skip loopback, point-to-point and down interfaces,
		 * except don't skip down interfaces
		 * if we're trying to get a list of configurable interfaces. */
		ioctl(LocalSock, SIOCGIFFLAGS, &ifReq);
		if ((ifReq.ifr_flags & IFF_LOOPBACK) ||
			(!(ifReq.ifr_flags & IFF_UP))) {
			continue;
		}
		if (pifReq->ifr_addr.sa_family == AF_INET) {
			/* Get a pointer to the address...*/
			memcpy(&LocalAddr, &pifReq->ifr_addr,
				sizeof pifReq->ifr_addr);
			/* We don't want the loopback interface. */
			if (LocalAddr.sin_addr.s_addr ==
				htonl(INADDR_LOOPBACK)) {
				continue;
			}
		}
		/* increment j if we found an address which is not loopback
		 * and is up */
		j++;
	}
	close(LocalSock);

	return LocalAddr.sin_addr.s_addr;
#endif
}


/*---------------------------------------------------------------------------*/
/*																			 */
/*---------------------------------------------------------------------------*/
int main(int argc, char* argv[]) {
  DiscoveredList dlist;
  char* query_arg;
  int sock;
  char *arg_val;
  int timeout = 5, count = 1;
  struct in_addr host = { INADDR_ANY };

  // get debug argument
  debug_mode = get_arg(argc, argv, "-d", NULL);

  // get timeout argument
  if (get_arg(argc, argv, "-t", &arg_val)) timeout = atoi(arg_val);

   // get host argument
  if (get_arg(argc, argv, "-h", &arg_val)) host.s_addr = inet_addr(arg_val);

  // get count argument
  if (get_arg(argc, argv, "-c", &arg_val)) count = atoi(arg_val);

  // last argument should be query
  query_arg = argv[argc-1];

  if (query_arg[0] != '_') {
	  printf("usage: mdnssd [-h <interface>] [-t <duration>] [-c <count>] [-d] <query>\n");
	  return 1;
  }

#ifdef _WIN32
   winsock_init();
#endif

  if (host.s_addr == INADDR_ANY) host.s_addr = get_localhost();

  sock = init_mDNS(debug_mode, host);

  if (sock < 0) {
	printf("cannot open socket\n");
	exit(1);
  }

  printf("using interface %s\n", inet_ntoa(host));

  while (count--) {

	query_mDNS(sock, query_arg, &dlist, timeout);
	print_discovered(&dlist);
	printf("===============================================================\n");
	free_discovered_list(&dlist);
  }

  close_mDNS(sock);

#ifdef _WIN32
  winsock_close();
#endif

  return 0;
}