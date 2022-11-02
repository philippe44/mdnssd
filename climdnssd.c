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
#include <iphlpapi.h>
#pragma comment(lib, "IPHLPAPI.lib")
typedef uint32_t in_addr_t;
#elif defined (__linux__) || defined (__FreeBSD__) || defined(sun)
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ifaddrs.h>
#if defined(sun)
#include <sys/sockio.h>
#endif
#if defined (__FreeBSD__)
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

#include "mdnssd.h"

static int debug_mode;
static bool verbose;

/*---------------------------------------------------------------------------*/
bool print_services(mDNSservice_t *slist, void *cookie, bool *stop) {
	mDNSservice_t *s;

	for (s = slist; s; s = s->next) {
		char *host = strdup(inet_ntoa(s->host));
		//printf("[%s] %s\t%05hu\t%-25s %s %us %s\n", host, inet_ntoa(s->addr), s->port,
		printf("[%s] %s\t%05hu\t%s %us %s\n", host, inet_ntoa(s->addr), s->port,
			   /*s->hostname, */s->name, s->since, s->expired ? "EXPIRED" : "ACTIVE");
		free(host);
		if (verbose) {
			for (int i = 0; i < s->attr_count; i++) {
			  printf(" %s =  %s\n", s->attr[i].name, s->attr[i].value);
			}
		}
	}

	printf("------------------------------\n");

	/* options to control loop
	control_mDNS((struct mDNShandle_s*) cookie, MDNS_RESET);
	control_mDNS((struct mDNShandle_s*) cookie, MDNS_SUSPEND);
	*stop = true;
	*/

	// we have not released the slist
	return false;
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
struct in_addr get_interface(char* iface) {
	struct in_addr addr;

	// try to get the address from the parameter
	addr.s_addr = iface && *iface ? inet_addr(iface) : INADDR_NONE;

	// if we already are given an address; just use it
	if (addr.s_addr != INADDR_NONE)  return addr;
#ifdef _WIN32
	struct sockaddr_in* host = NULL;
	ULONG size = sizeof(IP_ADAPTER_ADDRESSES) * 32;

	// otherwise we need to loop and find somethign that works
	IP_ADAPTER_ADDRESSES* adapters = (IP_ADAPTER_ADDRESSES*)malloc(size);
	int ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST, 0, adapters, &size);

	for (PIP_ADAPTER_ADDRESSES adapter = adapters; adapter; adapter = adapter->Next) {
		if (adapter->TunnelType == TUNNEL_TYPE_TEREDO ||
			adapter->OperStatus != IfOperStatusUp || 0)
			continue;

		char name[256];
		wcstombs(name, adapter->FriendlyName, sizeof(name));
		if (iface && *iface && stricmp(iface, name)) continue;

		for (IP_ADAPTER_UNICAST_ADDRESS* unicast = adapter->FirstUnicastAddress; unicast;
			unicast = unicast->Next) {
			if (adapter->FirstGatewayAddress && unicast->Address.lpSockaddr->sa_family == AF_INET) {
				addr = ((struct sockaddr_in*)unicast->Address.lpSockaddr)->sin_addr;
				return addr;
			}
		}
	}

	return addr;
#else
	struct ifaddrs* ifaddr;

	if (getifaddrs(&ifaddr) == -1) 	return addr;

	for (struct ifaddrs* ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET ||
			!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_MULTICAST) ||
			ifa->ifa_flags & IFF_LOOPBACK ||
			(iface && *iface && strcasecmp(iface, ifa->ifa_name)))
			continue;

		addr = ((struct sockaddr_in*)ifa->ifa_addr)->sin_addr;
		break;
	}

	freeifaddrs(ifaddr);
	return addr;
#endif
}

/*---------------------------------------------------------------------------*/
/*																			 */
/*---------------------------------------------------------------------------*/
int main(int argc, char* argv[]) {
  char* query_arg;
  struct mDNShandle_s *handle;
  char *arg_val, *addr = NULL;
  int timeout = 0, count = 1;
  struct in_addr host = { INADDR_ANY };

  // get debug argument
  debug_mode = get_arg(argc, argv, "-d", NULL);

  // get verbosity argument
  verbose = get_arg(argc, argv, "-v", NULL);

  // get timeout argument
  if (get_arg(argc, argv, "-t", &arg_val)) timeout = atoi(arg_val);

   // get host argument
  if (get_arg(argc, argv, "-h", &arg_val)) addr = arg_val;

  // get count argument
  if (get_arg(argc, argv, "-c", &arg_val)) count = atoi(arg_val);

  // last argument should be query
  query_arg = argv[argc-1];

  if (query_arg[0] != '_') {
	  printf("usage: mdnssd [-h <ip|iface>] [-v] [-t <duration>] [-c <count>] [-d] <query>\n");
	  return 1;
  }

#ifdef _WIN32
   winsock_init();
#endif

  host = get_interface(addr);
  handle = init_mDNS(debug_mode, host);

  if (!handle) {
	printf("cannot open socket\n");
	exit(1);
  }

  printf("using interface %s\n", inet_ntoa(host));

  while (count--) {
	query_mDNS(handle, query_arg, 0, timeout, &print_services, (void*) handle);
	printf("===============================================================\n");
	control_mDNS(handle, MDNS_RESET);
  }

  close_mDNS(handle);

#ifdef _WIN32
  winsock_close();
#endif

  return 0;
}