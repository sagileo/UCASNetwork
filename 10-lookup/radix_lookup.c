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

#define TYPE_EXTRANODE 1
#define TYPE_INTRANODE 0

struct radix_t
{
    u8 type;    // leaf (1) or internal node (0)
    u8 len;     // prefix length
    u16 port;    // only leaf has valid port value
    struct radix_t* left;
    struct radix_t* right;
};

double usec_time_diff(struct timeval *start, struct timeval *end);
int radix_route_add(struct radix_t *root, u32 addr, int prefixlen, u16 port);
int route_add(struct radix_t **node, u32 addr, int prefixlen, u16 port, u32 depth);
u16 radix_lookup(struct radix_t *root, u32 addr);
u16 route_lookup(struct radix_t *root, u32 addr, u32 depth, struct radix_t *extra_node);



int main()
{
    struct timeval tv1, tv2, tv3, tv4;

    FILE* fp = NULL;
    struct radix_t *root;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    u16 port;
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;

    char filename[] = "/home/ucas/ComputerNetwork/10-lookup/forwarding-table.txt";
    fp = fopen(filename, "r");
    if ( NULL == fp ) {
        printf("file open failed: %s\n", filename);
        return -1;
    }

    root = (struct radix_t*)malloc(sizeof(struct radix_t));
    bytes += sizeof(struct radix_t);
    memset(root, 0, sizeof(struct radix_t));

    if ( NULL == root ) {
        printf("radix init failed\n");
        return -1;
    }

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

        ret = radix_route_add(root, addr1, prefixlen, port);
        if ( ret < 0 ) {
            return -1;
        }
        i++;
    }
    printf("building radix tree finished\n");

    gettimeofday(&tv1, NULL);

    u64 num = 0xffffffffULL;
    for ( i = 0; i < num; i+=0x100 ) {
        radix_lookup(root, i);
    }

    gettimeofday(&tv2, NULL);
    fprintf(stdout, "radix lookup time per lookup: %.2lf ns.\nRAM consumed: %d bytes\n", 
                1000 * usec_time_diff(&tv1, &tv2) / (num/0x100), bytes);
//1.1.113.0
    // prefix[0] = 1; prefix[1] = 1; prefix[2] = 113; prefix[3] = 0; 
    // addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
    //         + ((u32)prefix[2] << 8) + (u32)prefix[3];
    // printf("%d\n", radix_lookup(root, addr1));
}


int radix_route_add(struct radix_t *root, u32 addr, int prefixlen, u16 port)
{
    return route_add(&root, addr, prefixlen, port, 0);
}

int route_add(struct radix_t **node, u32 addr, int prefixlen, u16 port, u32 depth)
{
    int ret;
    if(*node == NULL)
    {
        *node = (struct radix_t *)malloc(sizeof(struct radix_t));
        bytes += sizeof(struct radix_t);
        (*node)->type = TYPE_INTRANODE;
        (*node)->left = NULL;
        (*node)->right = NULL;
    }
    if(prefixlen == depth)      // matched
    {
        (*node)->type = TYPE_EXTRANODE;
        (*node)->port = port;
        (*node)->len = prefixlen;
        return 0;
    } else
    {
        if((addr >> (32 - depth - 1)) & 1)
            return route_add(&((*node)->right), addr, prefixlen, port, depth+1);
        else
            return route_add(&((*node)->left), addr, prefixlen, port, depth+1);
    }
}

u16 radix_lookup(struct radix_t *root, u32 addr)
{
    return route_lookup(root, addr, 0, NULL);
}

u16 route_lookup(struct radix_t *node, u32 addr, u32 depth, struct radix_t *extra_node)
{
    if(node == NULL)
        return -1;
    if(node->type == TYPE_EXTRANODE)
        extra_node = node;
    if((addr >> (32 - depth - 1)) & 1)
    {
        if(node->right == NULL)
        {
            if(extra_node != NULL)
                return extra_node->port;
            else
                return -1;
        }
        else
            return route_lookup(node->right, addr, depth + 1, extra_node);
    } else
    {
        if(node->left == NULL)
        {
            if(extra_node != NULL)
                return extra_node->port;
            else
                return -1;
        }
        else 
            return route_lookup(node->left, addr, depth + 1, extra_node);
    }
}

double usec_time_diff(struct timeval *start, struct timeval *end)
{
    return ((end->tv_sec - start->tv_sec)*1000000 + (end->tv_usec - start->tv_usec));
}