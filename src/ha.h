#include "cdada/queue.h"

/*Global variables*/
typedef void (*queue_thread_handler)();

// A linked list (LL) node to store a queue entry
typedef struct QNode
{
    void *key; //Data
    size_t key_len; //Data length
    long long timestamp;
}nodestruct;

/*Functions*/
extern void pm_ha_countdown_delete();
extern void pm_ha_queue_thread_wrapper();
extern int pm_ha_queue_produce_thread(void *);
extern void enQueue(cdada_queue_t*, void *, size_t);