#include "autoconf.h"
#include "dfu_header.h"
#include "api/print.h"
#include "api/regutils.h"


/* This file abstracts all the DFU related local cryptography primitives (local
 * to the platform, the token operations are handled in the DFU token specific files)
 */

void dfu_print_header(dfu_update_header_t *header){
	if(header == NULL){
		return;
	}
	printf("MAGIC = %x", header->magic);
	printf("\nTYPE  = %x", header->type);
	printf("\nVERSION = %x", header->version);
	printf("\nLEN = %x", header->len);
	printf("\nSIGLEN = %x", header->siglen);
	printf("\nCHUNKSIZE = %x", header->chunksize);	
	printf("\nIV = ");
	hexdump((unsigned char*)&(header->iv), 16);
	printf("\nHMAC = ");
	hexdump((unsigned char*)&(header->hmac), 16);
}

int dfu_parse_header(uint8_t *buffer, uint32_t len, dfu_update_header_t *header, uint8_t *sig, uint32_t siglen)
{
	/* Some sanity checks */
	if((buffer == NULL) || (header == NULL) || (sig == NULL)){
		goto err;
	}
	if(len < sizeof(dfu_update_header_t)){
		goto err;
	}
	/* Copy the header from the buffer */
	memcpy(header, buffer, sizeof(dfu_update_header_t));
    /* FIXME: define arch independent endianess management (to_device(xxx) instead of to_big/to_little */
    header->siglen    = to_big32(header->siglen);
    header->chunksize = to_big32(header->chunksize);
    header->len       = to_big32(header->len);
    header->magic     = to_big32(header->magic);
	/* Get the signature length */
	if(header->siglen > siglen){
		/* Not enough room to store the signature */
		goto err;
	}
	if(len < sizeof(dfu_update_header_t)+header->siglen){
		/* The provided buffer is too small! */
		goto err;
	} 
	/* Copy the signature */
	memcpy(sig, buffer+sizeof(dfu_update_header_t), header->siglen);

	return 0;
err:
	return -1;
}
