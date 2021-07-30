#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <string.h>

#include "poptrie/poptrie.h"

double usec_time_diff(struct timeval *start, struct timeval *end);

int main()
{
    struct timeval tv1, tv2, tv3, tv4;

    FILE* fp = NULL;
    struct poptrie *poptrie;
    char buf[4096];
    int prefix[4];
    int prefixlen;
    u16 port;
    int ret;
    u32 addr1;
    u32 addr2;
    u64 i;

    char filename[] = "forwarding-table.txt";
    fp = fopen(filename, "r");
    if ( NULL == fp ) {
        printf("file open failed: %s\n", filename);
        return -1;
    }

    poptrie = poptrie_init(NULL, 19, 22);

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

        ret = poptrie_route_add(poptrie, addr1, prefixlen, (void*)(u64)port);
        if ( ret < 0 ) {
            return -1;
        }
        i++;
    }
    printf("building poptrie finished\n");

    gettimeofday(&tv1, NULL);

    int num = 0xffffffffULL;
    for ( i = 0; i < num; i+=0x100 ) {
        poptrie_lookup(poptrie, i);
    }

    gettimeofday(&tv2, NULL);
    fprintf(stdout, "poptrie_lookup time per lookup: %.2lf ns.\n", 
                1000 * usec_time_diff(&tv1, &tv2) / (num/0x100));

    gettimeofday(&tv1, NULL);

    for ( i = 0; i < num; i++ ) {
        poptrie_rib_lookup(poptrie, i);
    }

    gettimeofday(&tv2, NULL);
    fprintf(stdout, "poptrie_rib_lookup time per lookup: %.2lf ns.\n", 
                1000 * usec_time_diff(&tv1, &tv2) / num);
//1.1.113.0
    // prefix[0] = 1; prefix[1] = 1; prefix[2] = 113; prefix[3] = 0; 
    // addr1 = ((u32)prefix[0] << 24) + ((u32)prefix[1] << 16)
    //         + ((u32)prefix[2] << 8) + (u32)prefix[3];
    // printf("%d\n", radix_lookup(root, addr1));
}

double usec_time_diff(struct timeval *start, struct timeval *end)
{
    return ((end->tv_sec - start->tv_sec)*1000000 + (end->tv_usec - start->tv_usec));
}