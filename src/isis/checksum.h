#ifndef _CHECKSUM_H_
#define _CHECKSUM_H_

extern int in_cksum(void *, int);
extern u_int16_t fletcher_checksum(u_char *, const size_t, const uint16_t);

#endif /* _CHECKSUM_H_ */
