/*Global variables*/
struct Queue *q_handler;
pthread_mutex_t mutex_thr;
pthread_cond_t sig;
typedef void (*queue_thread_handler)();

// A linked list (LL) node to store a queue entry
struct QNode
{
    void *key; //Data
    size_t key_len; //Data length
    long long timestamp;
    // struct QNode *next;
};

// The queue, front stores the front node of LL and rear stores the
// last node of LL
struct Queue
{
    // struct QNode *front, *rear;
    queue_thread_handler th_hdlr;
    // struct pm_list *q;
};

/*Functions*/
extern void countdown_delete();
extern void queue_thread_wrapper();
extern int queue_produce_thread(void *);
extern void enQueue(struct pm_list *, void *value, size_t value_len);
extern void deQueue(struct pm_list *);
// extern int getCount(struct Queue *);