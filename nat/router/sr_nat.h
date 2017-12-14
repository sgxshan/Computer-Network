
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>

#define closed 1
#define outbd_dyn 2
#define outbd_syn 3
#define inbd_syn 4
#define establish 5
#define outbd_fin 6
#define inbd_fin 7


typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp
  /* nat_mapping_udp, */
} sr_nat_mapping_type;

struct sr_nat_connection {
    /* add TCP connection state data members here */
    uint32_t ip;
    int conns_state;
    time_t last_updated;
    struct sr_nat_connection *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  int query_timeout;
  int established_timeout;
  int transitory_timeout;
    
  struct sr_nat_mapping *mappings;
  struct sr_instance *sr;
  struct inbd_syn_t *inbd_syn_packet;
  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


struct inbd_syn_t
{
    uint8_t *packet;
    uint16_t port;
    time_t last_updated;
    struct inbd_syn_t *next;
};

int   sr_nat_init(struct sr_nat *nat);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *nat_ptr);  /* Periodic Timout */
void mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping* mapping);
void syn_handler( struct sr_nat *nat);
struct sr_nat_connection *sr_lookup_conn(struct sr_nat_mapping *mapping, uint32_t ip);
void syn_packet_destroy(struct sr_nat *nat, struct inbd_syn_t *inbd_syn_packet);
struct sr_nat_connection *sr_nat_insert_connection(struct sr_nat_mapping *mapping, uint32_t ip);
/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance* sr, struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );


#endif
