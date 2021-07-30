#ifndef __MOSPF_DATABASE_H__
#define __MOSPF_DATABASE_H__

#include "base.h"
#include "list.h"

#include "mospf_proto.h"

extern struct list_head mospf_db;

typedef struct {
	struct list_head list;
	u32	rid;		// router which sends the LSU message
	u16	seq;		// sequence number of the LSU message
	int nadv;		// number of advertisement
	int alive;		
	struct mospf_lsa *array;	// (network. mask, id)
} mospf_db_entry_t;

void init_mospf_db();

#endif
