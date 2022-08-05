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
extern void countdown_delete();
extern void queue_thread_wrapper();
extern int queue_produce_thread(void *);
extern void enQueue(cdada_queue_t* q, void *value, size_t value_len);
// extern int getCount(struct Queue *);