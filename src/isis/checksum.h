#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

#if (!defined __CHECKSUM_C)
#define EXT extern
#else
#define EXT
#endif
EXT int in_cksum(void *, int);
EXT u_int16_t fletcher_checksum(u_char *, const size_t, const uint16_t);
#undef EXT

#endif /* _CHECKSUM_H_ */
