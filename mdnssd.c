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

#include "mdnssd-itf.h"

static int debug_mode;

void print_discovered(DiscoveredList *dlist) {
  int i;

  for(i=0; i < dlist->count; i++) {
	int j;
	printf("%s\t%s\t%u\t%s\n", dlist->items[i].hostname, inet_ntoa(dlist->items[i].addr), dlist->items[i].port, dlist->items[i].name);
	if (debug_mode) {
		for (j=0; j < dlist->items[i].attr_count; j++) {
		  printf("\t%s =  %s\n", dlist->items[i].attr[j].name, dlist->items[i].attr[j].value);
		}
	}
  }
}

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

#if WIN
void winsock_init(void) {
	WSADATA wsaData;
	WORD wVersionRequested = MAKEWORD(2, 2);
	int WSerr = WSAStartup(wVersionRequested, &wsaData);
	if (WSerr != 0) {
		exit(1);
	}
}

void winsock_close(void) {
	WSACleanup();
}
#endif


int main(int argc, char* argv[]) {
  DiscoveredList dlist;
  char* query_arg;
  int sock;
  char *arg_val;
  int timeout = 5, count = 1;
  uint32_t host = INADDR_ANY;

  // get debug argument
  debug_mode = get_arg(argc, argv, "-d", NULL);

  // get timeout argument
  if (get_arg(argc, argv, "-t", &arg_val)) timeout = atoi(arg_val);

   // get host argument
  if (get_arg(argc, argv, "-h", &arg_val)) host = inet_addr(arg_val);

  // get count argument
  if (get_arg(argc, argv, "-c", &arg_val)) count = atoi(arg_val);

  // last argument should be query
  query_arg = argv[argc-1];

  if (query_arg[0] != '_') {
	  printf("v1.1.1 usage: mdnssd [-h <interface>] [-t <duration>] [-c <count>] [-d] <query>\n");
	  return 1;
  }

#if WIN
   winsock_init();
#endif
   sock = init_mDNS(debug_mode, host);

  if (sock < 0) {
	printf("cannot open socket\n");
	exit(1);
  }

 while (count--) {

	query_mDNS(sock, query_arg, &dlist, timeout);
	print_discovered(&dlist);
	printf("===============================================================\n");
	free_discovered_list(&dlist);
  }

  close_mDNS(sock);

#if WIN
  winsock_close();
#endif

  return 0;
}