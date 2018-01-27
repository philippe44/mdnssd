#include "mdnssd-itf.h"

#if !defined(_WIN32)
#define closesocket close
#endif

#define DNS_HEADER_SIZE (12)
#define DNS_MAX_HOSTNAME_LENGTH (253)
#define DNS_MAX_LABEL_LENGTH (63)
#define MDNS_MULTICAST_ADDRESS "224.0.0.251"
#define MDNS_PORT (5353)
#define DNS_BUFFER_SIZE (32768)

// TODO find the right number for this
#define DNS_MESSAGE_MAX_SIZE (4096)

// DNS Resource Record types
// (RFC 1035 section 3.2.2)
#define DNS_RR_TYPE_A (1)
#define DNS_RR_TYPE_CNAME (5)
#define DNS_RR_TYPE_PTR (12)
#define DNS_RR_TYPE_TXT (16)
#define DNS_RR_TYPE_SRV (33)

// TODO not sure about this
#define MAX_RR_NAME_SIZE (256)
#define MAX_DEREFERENCE_COUNT (40)

#define NFREE(p) { if (p) free(p); }

struct mDNSMessageStruct{
  uint16_t id;
  uint16_t flags;
  uint16_t qd_count;
  uint16_t an_count;
  uint16_t ns_count;
  uint16_t ar_count;
  char* data;
  size_t data_size;
};
//} __attribute__((__packed__)); // ensure that struct is packed
typedef struct mDNSMessageStruct mDNSMessage;

typedef struct {
  int qr;
  int opcode;
  int aa;
  int tc;
  int rd;
  int ra;
  int zero;
  int ad;
  int cd;
  int rcode;
} mDNSFlags;

typedef struct {
  char* qname;
  uint16_t qtype;
  uint16_t qclass;
  int prefer_unicast_response;
} mDNSQuestion;

typedef struct {
  char* name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rdata_length;
  void* rdata;
} mDNSResourceRecord;

typedef struct slist_s {
  struct slist_s *next;
  enum {MDNS_CURRENT = 0, MDNS_UPDATED, MDNS_EXPIRED} status;
  uint32_t eol[3], seen;
  char *name, *hostname;
  struct in_addr addr, host;
  uint16_t port;
  int txt_length;
  char *txt;
} slist_t;

typedef struct alist_s {
  struct alist_s *next;
  uint32_t eol;
  char *name;
  struct in_addr addr;
} alist_t;

typedef struct mDNShandle_s {
	int sock;
	enum { MDNS_IDLE, MDNS_RUNNING } state;
	mDNScontrol_e control;
	uint32_t last;
	struct context_s {
		char *query;
		uint32_t ttl;
		slist_t *slist;
		alist_t *alist;
	} context;
} mDNShandle_t;

typedef struct item_s {
	struct item_s *next;
} item_t;

typedef int compare_list_f(void *a, void *b);

static item_t *remove_item(item_t *a, item_t **list);
static item_t *insert_item(item_t *a, item_t **list);
/*
static item_t *insert_ordered_item(item_t *a, item_t **list, compare_list_f *compare);
static item_t *insert_tail_item(item_t *item, item_t **list);
*/
static void   clear_list(item_t *list, void (*clean)(void *));

static void store_a(struct context_s *context, mDNSResourceRecord* rr);
static void store_other(struct in_addr host, struct context_s *context, char *message, mDNSResourceRecord* rr);

static int debug(const char* format, ...);

static mDNSFlags* mdns_parse_header_flags(uint16_t data);
static uint16_t mdns_pack_header_flags(mDNSFlags flags);
static char* mdns_pack_question(mDNSQuestion* q, size_t* size);
static void mdns_message_print(mDNSMessage* msg);
static mDNSMessage* mdns_build_query_message(char* query, uint16_t query_type);
static char* mdns_pack_message(mDNSMessage* msg, size_t* pack_length);

static int mdns_parse_question(char* message, char* data, int size);

static int mdns_parse_rr_a(char* data, struct in_addr *addr);
static int mdns_parse_rr_ptr(char* message, char* data, char **name);
static int mdns_parse_rr_srv(char* message, char* data, char **hostname, unsigned short *port);
static void mdns_parse_rr_txt(char* message, mDNSResourceRecord* rr, char **txt, int *length);
static int mdns_parse_rr(struct in_addr host, struct context_s *context, char* message, char* rrdata, int size, int is_answer);
static int mdns_parse_message_net(struct in_addr host, struct context_s *context, char* data, int size, mDNSMessage* msg);
static char* parse_rr_name(char* message, char* name, int *parsed);

static uint16_t get_offset(char* data);

static void free_resource_record(mDNSResourceRecord* rr);
static void clear_context(struct context_s *context);

static char* prepare_query_string(char* name);
static int send_query(int sock, char* query, uint16_t query_type);



