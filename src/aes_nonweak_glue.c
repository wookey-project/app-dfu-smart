#include "aes.h"

#if 1
/* Weak symbols to handle objects removal */
#ifdef CONFIG_USR_LIB_AES_ALGO_UNMASKED
int aes_soft_unmasked_setkey_enc(UNUSED_ATTR aes_soft_unmasked_context *ctx, UNUSED_ATTR const uint8_t *key, UNUSED_ATTR uint32_t keybits){
    return 1;
}
int aes_soft_unmasked_setkey_dec(UNUSED_ATTR aes_soft_unmasked_context *ctx, UNUSED_ATTR const uint8_t *key, UNUSED_ATTR uint32_t keybits){
    return 1;
}
int aes_soft_unmasked_enc(UNUSED_ATTR aes_soft_unmasked_context *ctx, UNUSED_ATTR const uint8_t data_in[16], UNUSED_ATTR uint8_t data_out[16]){
    return 1;
}
int aes_soft_unmasked_dec(UNUSED_ATTR aes_soft_unmasked_context *ctx, UNUSED_ATTR const uint8_t data_in[16], UNUSED_ATTR uint8_t data_out[16]){
    return 1;
}
#endif
#endif

#if 0
/* Weak symbols to handle objects removal */
#ifdef CONFIG_USR_LIB_AES_ALGO_ANSSI_MASKED
UINT aes(UNUSED_ATTR UCHAR Mode, UNUSED_ATTR STRUCT_AES* struct_aes, UNUSED_ATTR const UCHARp key, UNUSED_ATTR const UCHARp input, UNUSED_ATTR UCHARp output, UNUSED_ATTR const UCHARp random_key, UNUSED_ATTR const UCHARp random_aes){
    return 1;
}
#endif
#endif
