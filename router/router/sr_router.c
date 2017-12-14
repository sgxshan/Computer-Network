/**********************************************************************
 * name: xin shan
 * id: 1003683409
 * username: shanxin
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>



#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    
    /*check packet length*/
    if(len <sizeof (sr_ethernet_hdr_t))
        printf("packet does not satisfy mininum length requirement \n");
    
    /*it is an ARP packet*/
    if (ntohs(eth_hdr->ether_type) == ethertype_arp)
        arp_handler(sr, packet, len, interface);
    
    /*it is an IP packet*/
    if (ntohs(eth_hdr->ether_type) == ethertype_ip)
        ip_handler(sr, packet, len, interface);

}/* end sr_ForwardPacket */


void arp_handler (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
    sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    sr_ethernet_hdr_t *eth_hdr = (sr_ethernet_hdr_t *) packet;
    struct sr_if *itface = get_ip_interface(sr,arp_hdr->ar_tip);
    
    if(len < sizeof (sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
        printf("packet does not satisfy mininum length requirement \n");
    
    /*request to me*/
    if (ntohs(arp_hdr->ar_op) == arp_op_request) {
        /*constrct an ARP reply*/
        unsigned int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
        uint8_t *new_arp = malloc(length);
        
        /*ethernet header*/
        sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_arp;
        memcpy(new_eth_hdr->ether_shost, sr_get_interface(sr, interface)->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
        memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
        new_eth_hdr->ether_type = htons(ethertype_arp);
        
        /*arp header*/
        sr_arp_hdr_t *new_arp_hdr = (sr_arp_hdr_t *)(new_arp + sizeof(sr_ethernet_hdr_t));
        new_arp_hdr->ar_hrd = arp_hdr->ar_hrd;
        new_arp_hdr->ar_pro = arp_hdr->ar_pro;
        new_arp_hdr->ar_hln = arp_hdr->ar_hln;
        new_arp_hdr->ar_pln = arp_hdr->ar_pln;
        new_arp_hdr->ar_op =  htons(arp_op_reply);
        memcpy(new_arp_hdr->ar_sha, itface->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
        new_arp_hdr->ar_sip =  itface->ip;
        memcpy(new_arp_hdr->ar_tha, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
        new_arp_hdr->ar_tip = arp_hdr->ar_sip;
        
        /*send it back*/
        sr_send_packet(sr, new_arp, length,  itface->name);
        free(new_arp);
    }
    
    /*reply to me*/
    if (ntohs(arp_hdr->ar_op) == arp_op_reply) {
        /*cache and go through request queue*/
        struct sr_arpreq *request = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);
        if (request){
            struct sr_packet *req_packet = request->packets;
            while (req_packet) {
                struct sr_if* itface = sr_get_interface(sr, req_packet->iface);
                sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *) req_packet->buf;
                memcpy(req_eth_hdr->ether_dhost, arp_hdr->ar_sha, sizeof(unsigned char)*ETHER_ADDR_LEN);
                memcpy(req_eth_hdr->ether_shost, itface->addr, sizeof(unsigned char)*ETHER_ADDR_LEN);
                print_hdrs(req_packet->buf, req_packet->len);
                /*send outstanding packets*/
                sr_send_packet(sr, req_packet->buf, req_packet->len, req_packet->iface);
                req_packet = req_packet->next;
            }
        }
        sr_arpreq_destroy(&sr->cache, request);
    }
    
}

void ip_handler (struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *) packet;
    sr_ip_hdr_t * ip_hdr = (sr_ip_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t*)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    struct sr_if *itface = get_ip_interface (sr, ip_hdr->ip_dst);
    
    /*check the packet length*/
    if (len<sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
        printf("IP packet does not satisfy mininum length requirement \n");
    
    
    /*check check_sum*/
    uint16_t prev_cksum = ip_hdr->ip_sum;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));   /*recalculate check sum*/
    
    /*incorrect check sum*/
    if (prev_cksum != ip_hdr->ip_sum)
        printf("Incorrect check sum!\n");
    
    /*not for me*/
    if(!itface){
        ip_hdr->ip_ttl--;        /*decrease ttl by 1*/
        if(ip_hdr->ip_ttl>0){
            /*recomputer check_sum*/
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        }
        else
            /*time exceeded(type 11, code 0)*/
            icmp_handler(sr, eth_hdr, ip_hdr, interface,11,0);
        
        /*find entry in the route table have longest prefix match*/
        struct sr_rt* ip_dst_lpm = get_lpm (sr, ip_hdr->ip_dst);
        if (ip_dst_lpm) {
            struct sr_if *out_if = sr_get_interface(sr, ip_dst_lpm->interface);
            
            /*check ARO cache for next hop*/
            struct sr_arpentry * arp_entry = sr_arpcache_lookup (&sr->cache, ip_dst_lpm->gw.s_addr);
            
            /*if there, send it*/
            if (arp_entry){
                memcpy(eth_hdr->ether_shost, out_if->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
                memcpy(eth_hdr->ether_dhost, arp_entry->mac, sizeof(unsigned char)*ETHER_ADDR_LEN);
                print_hdrs(packet, len);
                sr_send_packet (sr, packet, len, out_if->name);
                
            }
            /*otherwise send ARP request*/
            else {
                printf("not find in our ARP cache\n");
                struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, out_if->name);
                handle_arpreq(sr, req);
            }
            
        }
        
        else
            /*not find lpm destination net unreachable(type 3, code 0)*/
            icmp_handler(sr, eth_hdr, ip_hdr, interface, 3, 0);
    }
    
    /*it is for me */
    else {
        uint8_t ip_p = ip_protocol((uint8_t *)ip_hdr);
        
        /*check the packet length*/
        if (ip_p == ip_protocol_icmp) {
            if (len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
                printf("ICMP packet does not satisfy mininum length requirement \n");
            
            /*check check_sum*/
            uint16_t prev_cksum = icmp_hdr->icmp_sum;
            icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
            if(prev_cksum !=  icmp_hdr->icmp_sum){
                printf("Incorrect icmp check sum!\n");
            }
            
            /*it is ICMP echo req, send echo reply*/
            if (icmp_hdr->icmp_type == 8)
                echo_reply_handler(sr, packet, len, interface);
            
        }
        else
        /* or it is TCP/UDP, send ICMP port unreachable(type 3, code 3)*/
            icmp_handler(sr, eth_hdr, ip_hdr, interface,3,3);
        
    }
}

void icmp_handler(struct sr_instance* sr, sr_ethernet_hdr_t* eth_hdr, sr_ip_hdr_t* ip_hdr, char* interface, int type, int code){
    int length = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *new_packet = malloc(length);
    struct sr_rt *lpm = get_lpm(sr, ip_hdr->ip_src);
    struct sr_if* itface = sr_get_interface(sr, lpm->interface);
    
    /*ethernet header*/
    sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *)new_packet;
    memcpy(new_eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(new_eth_hdr->ether_shost, eth_hdr->ether_dhost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    new_eth_hdr->ether_type = htons(ethertype_ip);
    
    /*ip header*/
    sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_v = 4;
    new_ip_hdr->ip_hl = sizeof(sr_ip_hdr_t)/4;
    new_ip_hdr->ip_tos = 0;
    new_ip_hdr->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
    new_ip_hdr->ip_id = htons(0);
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_dst = ip_hdr->ip_src;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_src = code == 3 ? ip_hdr->ip_dst : itface->ip;
    new_ip_hdr->ip_sum = 0;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
    
    /*icmp header*/
    sr_icmp_t3_hdr_t *new_icmp_hdr = (sr_icmp_t3_hdr_t *)(new_packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;
    new_icmp_hdr->unused = 0;
    new_icmp_hdr->next_mtu = 0;
    new_icmp_hdr->icmp_sum = 0;
    memcpy(new_icmp_hdr->data, ip_hdr, ICMP_DATA_SIZE);
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));

    
    if (lpm){
        struct sr_arpentry *arp_entry = sr_arpcache_lookup(&sr->cache, lpm->gw.s_addr);
        if (arp_entry){
            
            /* change ethernet header */
            sr_ethernet_hdr_t *new_eth_hdr = (sr_ethernet_hdr_t *) new_packet;
            memcpy(new_eth_hdr->ether_dhost, arp_entry->mac, sizeof(uint8_t)*ETHER_ADDR_LEN);
            memcpy(new_eth_hdr->ether_shost, itface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
            
            /* change ip header */
            sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *) (new_packet + sizeof (sr_ethernet_hdr_t));
            new_ip_hdr->ip_sum = 0;
            new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
            
            sr_send_packet(sr, new_packet, length, itface->name);
            free(arp_entry);
        } else {
            /* If there is no match in our ARP cache, send ARP request. */
            struct sr_arpreq *req = sr_arpcache_queuereq(&sr->cache, lpm->gw.s_addr, new_packet, length, itface->name);
            handle_arpreq(sr, req);
        }
    }
    free (new_packet);
    
}

void echo_reply_handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface){
    sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t *)packet;
    sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t));
    struct sr_if* itface = sr_get_interface(sr, interface);
    
    /*change ethernet header*/
    memcpy(eth_hdr->ether_dhost, eth_hdr->ether_shost, sizeof(uint8_t)*ETHER_ADDR_LEN);
    memcpy(eth_hdr->ether_shost, itface->addr, sizeof(uint8_t)*ETHER_ADDR_LEN);
    
    /*change ip header*/
    uint32_t temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
    
    /*change icmp header*/
    icmp_hdr->icmp_type = 0;
    icmp_hdr->icmp_code = 0;
    icmp_hdr->icmp_sum = 0;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
    
    /*check ARO cache*/
    struct sr_arpentry * arp_entry = sr_arpcache_lookup (&sr->cache, ip_hdr->ip_dst);

    /*if there, send it*/
    if (arp_entry)
        sr_send_packet (sr, packet, len, interface);
    
    /*otherwise send ARP request*/
    else {
        struct sr_arpreq * req = sr_arpcache_queuereq(&sr->cache, ip_hdr->ip_dst, packet, len, interface);
        handle_arpreq(sr, req);
    }
    
}

struct sr_if* get_ip_interface (struct sr_instance* sr, uint32_t ip) {
    struct sr_if* walker = sr->if_list;
    /*travel all the link list until find correspnd ip*/
    while (walker){
            if (walker->ip == ip){
            return walker;
        }
        walker = walker->next;
    }
    return NULL;
}

struct sr_rt * get_lpm (struct sr_instance* sr, uint32_t ip_dst) {
    struct sr_rt* walker = sr->routing_table;
    struct sr_rt* longest_prefix = NULL;
    int max_len = 0;
    while (walker) {
        /*find longest prefix match*/
        if ((ip_dst & walker->mask.s_addr) == (walker->dest.s_addr & walker->mask.s_addr)) {
            if ((ip_dst & walker->mask.s_addr) > max_len){
                longest_prefix = walker;
                max_len = ip_dst & walker->mask.s_addr;
            }
        }
        walker = walker->next;
    }
    return longest_prefix;
}
