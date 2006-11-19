#define LABEL_MASK      0xfffff000
#define LABEL_SHIFT     12
#define EXP_MASK        0x00000e00
#define EXP_SHIFT       9
#define STACK_MASK      0x00000100
#define STACK_SHIFT     8
#define TTL_MASK        0x000000ff
#define TTL_SHIFT       0

#define MPLS_LABEL(x)   (((x) & LABEL_MASK) >> LABEL_SHIFT)
#define MPLS_EXP(x)     (((x) & EXP_MASK) >> EXP_SHIFT)
#define MPLS_STACK(x)   (((x) & STACK_MASK) >> STACK_SHIFT)
#define MPLS_TTL(x)     (((x) & TTL_MASK) >> TTL_SHIFT)

