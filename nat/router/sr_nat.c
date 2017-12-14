
#include <signal.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_nat.h"
#include "sr_router.h"
#include <unistd.h>

static int tcp_port = 1024;
static int icmp_id = 0;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  /* Initialize any variables here */
  nat->mappings = NULL;
  nat->inbd_syn_packet = NULL;
  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

    pthread_mutex_lock(&(nat->lock));

    /* free nat memory here */
    struct sr_nat_mapping *walker = nat->mappings;
    while(walker!=NULL){
        walker = nat->mappings;
        nat->mappings = walker->next;
        mapping_destroy(nat, walker);
    }
    
    pthread_kill(nat->thread, SIGKILL);
    return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void mapping_destroy(struct sr_nat *nat, struct sr_nat_mapping* mapping){
    struct sr_nat_mapping *prev = NULL;
    struct sr_nat_mapping *walker = nat->mappings;
    while(walker!=NULL){
        struct sr_nat_mapping *next = walker->next;
        if(walker==mapping){
            if(prev!=NULL)
                prev->next = next;
            else
                nat->mappings = next;
            free(mapping);
        }
        else
            prev = walker;
        walker = next;
    }
}

void connection_destroy(struct sr_nat_mapping *mapping, struct sr_nat_connection *conns ){
    struct sr_nat_connection *prev = NULL;
    struct sr_nat_connection *walker = mapping->conns;
    while(walker!=NULL){
        struct sr_nat_connection *next = walker->next;
        if(walker==conns){
            if(prev!=NULL)
                prev->next = next;
            else
                mapping->conns = next;
            free(mapping);
        }
        else
            prev = walker;
        walker = next;
    }
}

void syn_packet_destroy(struct sr_nat *nat, struct inbd_syn_t *inbd_syn_packet){
    struct inbd_syn_t *prev = NULL;
    struct inbd_syn_t *walker = nat->inbd_syn_packet;
    while(walker!=NULL){
        struct inbd_syn_t *next = walker->next;
        if(walker==inbd_syn_packet){
            if(prev!=NULL)
                prev->next = next;
            else
                nat->inbd_syn_packet = next;
            free(inbd_syn_packet);
        }
        else
            prev = walker;
        walker = next;
    }
}

void syn_handler( struct sr_nat *nat){
    time_t curtime = time(NULL);
    struct inbd_syn_t *inbd_syn_packet = nat->inbd_syn_packet;
    while(inbd_syn_packet!=NULL){
        if (difftime(curtime, inbd_syn_packet->last_updated) > 6){
            struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, inbd_syn_packet->port, nat_mapping_tcp);
            if (mapping==NULL){
                sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)(inbd_syn_packet->packet);
                sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (inbd_syn_packet->packet + sizeof(sr_ethernet_hdr_t));
                icmp_handler(nat->sr, eth_hdr, ip_hdr, "eth2", 3, 3);
            }
            else{
                struct inbd_syn_t *next = inbd_syn_packet->next;
                syn_packet_destroy(nat, inbd_syn_packet);
                inbd_syn_packet = next;
            }
            
        }
        inbd_syn_packet = inbd_syn_packet->next;
    }
}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
      sleep(1.0);
      pthread_mutex_lock(&(nat->lock));

      time_t curtime = time(NULL);
    
      /* handle periodic tasks here */
      syn_handler(nat);
      
      struct sr_nat_mapping *walker = nat->mappings;
      while(walker!=NULL){
          if(walker->type == nat_mapping_icmp){
              if (difftime(curtime, walker->last_updated) > nat->query_timeout){
                  struct sr_nat_mapping *next = walker->next;
                  mapping_destroy(nat, walker);
                  walker = next;
                  break;
              }
              else
                  walker = walker->next;
          }
          else
              walker = walker->next;
          if(walker!=NULL&&walker->type == nat_mapping_tcp){
              struct sr_nat_connection *conns = walker->conns;
              if(conns==NULL)
                  break;
              switch(conns->conns_state){
                  case establish:
                      if(difftime(curtime, conns->last_updated)>nat->established_timeout){
                          struct sr_nat_connection* next = conns->next;
                          connection_destroy(walker, conns);
                          conns = next;
                      }
                      break;
                  case inbd_syn:
                      if(difftime(curtime, conns->last_updated)>nat->transitory_timeout){
                          struct sr_nat_connection* next = conns->next;
                          connection_destroy(walker, conns);
                          conns = next;
                      }
                      break;
                  case outbd_syn:
                      if(difftime(curtime, conns->last_updated)>nat->transitory_timeout){
                          struct sr_nat_connection* next = conns->next;
                          connection_destroy(walker, conns);
                          conns = next;
                      }
                      break;
                  case inbd_fin:
                      if(difftime(curtime, conns->last_updated)>nat->transitory_timeout){
                          struct sr_nat_connection* next = conns->next;
                          connection_destroy(walker, conns);
                          conns = next;
                      }
                      break;
                  case outbd_fin:
                      if(difftime(curtime, conns->last_updated)>nat->transitory_timeout){
                          struct sr_nat_connection* next = conns->next;
                          connection_destroy(walker, conns);
                          conns = next;
                      }
                      break;
                  default: break;
              }
              
              walker = walker->next;
          }
      }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy */
    struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
    struct sr_nat_mapping *walker = nat->mappings;
    while(walker!=NULL){
        if(walker->aux_ext == aux_ext&&walker->type == type){
            memcpy(copy, walker, sizeof(struct sr_nat_mapping));
            pthread_mutex_unlock(&(nat->lock));
            return copy;
        }
        walker = walker->next;
    }
    pthread_mutex_unlock(&(nat->lock));
    return NULL;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle lookup here, malloc and assign to copy. */
    struct sr_nat_mapping *copy = malloc(sizeof(struct sr_nat_mapping));
    struct sr_nat_mapping *walker = nat->mappings;
    while(walker!=NULL){
        if(walker->ip_int == ip_int&&walker->aux_int == aux_int&&walker->type == type){
            memcpy(copy, walker, sizeof(struct sr_nat_mapping));
            pthread_mutex_unlock(&(nat->lock));
            return copy;
        }
        walker = walker->next;
    }
    pthread_mutex_unlock(&(nat->lock));
    return NULL;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_instance* sr, struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

    pthread_mutex_lock(&(nat->lock));

    /* handle insert here, create a mapping, and then return a copy of it */
    struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
    mapping->type = type;
    mapping->ip_int = ip_int;
    mapping->ip_ext = sr_get_interface(sr, "eth2")->ip;
    mapping->aux_int = aux_int;
    mapping->last_updated = time(NULL);
    mapping->conns = NULL;
    if(mapping->type == nat_mapping_icmp){
        mapping->aux_ext = icmp_id++;
    }
    if(mapping->type == nat_mapping_tcp){
        mapping->aux_ext = tcp_port++;
    }
    mapping->next = nat->mappings;
    nat->mappings = mapping;
    struct sr_nat_mapping *mapping_cpy = malloc(sizeof(struct sr_nat_mapping));
    memcpy(mapping_cpy, mapping, sizeof(struct sr_nat_mapping));
    pthread_mutex_unlock(&(nat->lock));
    return mapping_cpy;
}

struct sr_nat_connection *sr_nat_insert_connection(struct sr_nat_mapping *mapping, uint32_t ip) {
    struct sr_nat_connection *new_conn = malloc(sizeof(struct sr_nat_connection));
    struct sr_nat_connection *head = mapping->conns;
    new_conn->ip = ip;
    new_conn->last_updated = time(NULL);
    new_conn->conns_state = closed;
    new_conn->next = head;
    mapping->conns = new_conn;
    return  new_conn;
}

struct sr_nat_connection *sr_lookup_conn(struct sr_nat_mapping *mapping, uint32_t ip) {
    struct sr_nat_connection *walker = mapping->conns;
    while(walker!=NULL){
        if(walker->ip == ip){
            return walker;
        }
        else
            walker = walker->next;
    }
    return NULL;
}
