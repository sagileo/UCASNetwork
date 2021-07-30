#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdint.h>
#include <string.h>

//#include "poptrie/poptrie.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

int bytes;

#define TEST_PROGRESS()                              \
    do {                                             \
        printf(".");                                 \
        fflush(stdout);                              \
    } while ( 0 )

typedef struct poptrie_node
{
    u64 vector;
    struct poptrie_node* desc_nodes[64];
    u16 valid;
    int16_t leaf_val;
} poptrie_node_t;

struct poptrie
{
    poptrie_node_t *node;
};

double usec_time_diff(struct timeval *start, struct timeval *end);
int poptrie_route_add(struct poptrie *poptrie, u32 addr, int prefixlen, int16_t port);
int16_t poptrie_lookup(struct poptrie *poptrie, u32 addr);

int main()
{
    struct timeval tv1, tv2, tv3, tv4;

    FILE* fp = NULL;
    struct poptrie *poptrie;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    int16_t port;
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;

    poptrie = (struct poptrie *)malloc(sizeof(struct poptrie));
    bytes += sizeof(struct poptrie);

    fp = fopen("forwarding-table.txt", "r");
    if ( NULL == fp ) {
        printf("file open failed: forwarding-table.txt\n");
        return -1;
    }

    poptrie->node = (poptrie_node_t *)malloc(sizeof(poptrie_node_t));
    bytes += sizeof(poptrie_node_t);
    memset(poptrie->node, 0, sizeof(poptrie_node_t));

    i = 0;
    while ( !feof(fp) ) {
        if ( !fgets(buf, sizeof(buf), fp) ) {
            continue;
        }
        ret = sscanf(buf, "%d.%d.%d.%d %d %hd", &prefix[0], &prefix[1],
                     &prefix[2], &prefix[3], &prefixlen, &port);
        if ( ret < 0 ) {
            return -1;
        }

        addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
            + ((u32)prefix[2] << 8) + (u32)prefix[3];

        ret = poptrie_route_add(poptrie, addr1, prefixlen, port);
        if ( ret < 0 ) {
            return -1;
        }
        i++;
    }

    printf("building poptrie finished\n");
    gettimeofday(&tv1, NULL);

    u64 num = 0xffffffffULL;
    for ( i = 0; i < num; i+=0x100 ) {
        poptrie_lookup(poptrie, i);
    }

    gettimeofday(&tv2, NULL);
    fprintf(stdout, "poptrie_lookup time per lookup: %.2lf ns.\nRAM consumed: %d bytes\n", 
                1000 * usec_time_diff(&tv1, &tv2) / (num/0x100), bytes);
//1.1.113.0
    // prefix[0] = 1; prefix[1] = 1; prefix[2] = 113; prefix[3] = 0; 
    // port = 7;
    // prefixlen = 24;
    // addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
    //         + ((u32)prefix[2] << 8) + (u32)prefix[3];
    // poptrie_route_add(poptrie, addr1, prefixlen, port);
    // poptrie_route_add(poptrie, 0x10293847, 30, 3);
    // poptrie_route_add(poptrie, 0x10293847, 8, 7);
    // printf("%d %d\n", poptrie_lookup(poptrie, 0), poptrie_lookup(poptrie, 0x10293847));
}

int extract(unsigned int a, int offset, int len)
{
    if(offset > 31)
        return -1;
    if(offset + len > 32)
        len = 32 - offset;
    return ( (((1ULL << (32 - offset)) - 1) & ~( (1ULL << (32 - offset - len)) - 1)) & a ) >> (32 - offset - len);
}

int min(int a, int b)
{
    return a < b ? a : b;
}

int _poptrie_add(poptrie_node_t **node, u32 addr, int prefixlen, int16_t port, u32 depth)
{
    int ret;
    if(*node == NULL)
    {
        *node = (poptrie_node_t *)malloc(sizeof(poptrie_node_t));
        bytes += sizeof(poptrie_node_t);
        memset(*node, 0, sizeof(poptrie_node_t));
    }
    if(prefixlen <= depth)
    {
        (*node)->leaf_val = port;
        (*node)->valid = 1;
        return 0;
    }
    else
    {
        int v = extract(addr, depth, min(6, prefixlen - depth));
        (*node)->vector |= (1ULL << v);
        _poptrie_add(&((*node)->desc_nodes[v]), addr, prefixlen, port, depth + 6);
    }
}

int poptrie_route_add(struct poptrie *poptrie, u32 addr, int prefixlen, int16_t port)
{
    return _poptrie_add(&(poptrie->node), addr, prefixlen, port, 0);
}


int16_t _poptrie_lookup(poptrie_node_t *node, u32 addr, u32 depth, poptrie_node_t *extra_node)
{
    if(node == NULL)
        return -1;
    if(node->valid)
        extra_node = node;

    int v;
    int port = -1;
    int ret = -1;

    v = extract(addr, depth, 6);
    if(node->vector & (1ULL << v))
    {
        if(node->desc_nodes[v]->valid)
            port = node->desc_nodes[v]->leaf_val;
    }
    if((ret = _poptrie_lookup(node->desc_nodes[v], addr, depth + 6, extra_node)) == -1)
    {
        return port;
    }
    return ret;
}

int16_t poptrie_lookup(struct poptrie *poptrie, u32 addr)
{
    return _poptrie_lookup(poptrie->node, addr, 0, NULL);
}

double usec_time_diff(struct timeval *start, struct timeval *end)
{
    return ((end->tv_sec - start->tv_sec)*1000000 + (end->tv_usec - start->tv_usec));
}