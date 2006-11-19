/* defines */
#if defined IM_LITTLE_ENDIAN
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0x000000f0) == 0x000000e0)
#else
#define IS_IPV4_MULTICAST(a) ((((u_int32_t)(a)) & 0xf0000000) == 0xe0000000)
#endif
#define IS_IPV6_MULTICAST(a) (((const uint8_t *) (a))[0] == 0xff)

/* prototypes */
#if (!defined __ADDR_C)
#define EXT extern
#else
#define EXT
#endif
EXT unsigned int str_to_addr(const char *, struct host_addr *);
EXT unsigned int addr_to_str(char *, const struct host_addr *);
EXT unsigned int addr_to_sa(struct sockaddr *, struct host_addr *, u_int16_t);
EXT unsigned int sa_to_addr(struct sockaddr *, struct host_addr *, u_int16_t *);
EXT unsigned int sa_addr_cmp(struct sockaddr *, struct host_addr *);
EXT void *pm_htonl6(void *);
EXT void *pm_ntohl6(void *);
EXT u_int64_t pm_htonll(u_int64_t);
EXT u_int64_t pm_ntohll(u_int64_t);
EXT unsigned int ip6_addr_cmp(void *, void *);
EXT void ip6_addr_cpy(void *, void *);
EXT void etheraddr_string(const u_char *, char *);
EXT int string_etheraddr(const u_char *, char *);
EXT int is_multicast(struct host_addr *);
EXT void clean_sin_addr(struct sockaddr *);

#undef EXT
