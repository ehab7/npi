#include <stdio.h>
unsigned short customchecksum(const char *buf, unsigned end)
{
	unsigned sum = 0;
	unsigned size = end;
	int i;
		
	/* Accumulate checksum */
	for (i = 0; i < end - 1; i += 2)
	{
		
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);
	
	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}
/* tcp check to process both the pseudo header and the actual header*/
unsigned short tcpchecksum(const char *buf, const char *buf2, unsigned end)
{
	unsigned sum = 0;
	unsigned size = end;
	int i;
	
	for (i = 0; i < 32; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}
	/* Accumulate checksum */
	for (i = 0; i < end - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf2[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf2[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);
	
	return ~sum;
}
