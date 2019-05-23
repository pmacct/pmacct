
/* prototypes */
#if !defined(__MURMUR2_C)
#define EXT extern
#else
#define EXT
#endif
EXT unsigned int murmurhash2(const void *, int, const unsigned int);
#undef EXT
