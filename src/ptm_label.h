/* L1 - avro_new_label */

#ifndef PTM_LABEL
#define PTM_LABEL

/* Data structures */
typedef struct {
  char *key;
  char *value;
} __attribute__((packed)) ptm_label;

#endif