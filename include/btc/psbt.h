/*

 The MIT License (MIT)

 Copyright (c) 2020 Zhang Zengbo

 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the "Software"),
 to deal in the Software without restriction, including without limitation
 the rights to use, copy, modify, merge, publish, distribute, sublicense,
 and/or sell copies of the Software, and to permit persons to whom the
 Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included
 in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES
 OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 OTHER DEALINGS IN THE SOFTWARE.

*/

#ifndef __LIBBTC_PSBT_H__
#define __LIBBTC_PSBT_H__

#include "btc.h"
#include "vector.h"
#include "serialize.h"
#include "buffer.h"

LIBBTC_BEGIN_DECL

typedef enum _PSBT_GLOBAL_TYPES {
    PSBT_GLOBAL_UNSIGNED_TX = 0,
    PSBT_GLOBAL_XPUB = 1,
    PSBT_GLOBAL_VERSION = 0xFB,
    PSBT_GLOBAL_PROPRIETARY = 0xFC
} PSBT_GLOBAL_TYPES;

typedef enum _PSBT_INPUT_TYPES {
    PSBT_IN_NON_WITNESS_UTXO = 0,
    PSBT_IN_WITNESS_UTXO = 1,
    PSBT_IN_PARTIAL_SIG  = 2,
    PSBT_IN_SIGHASH_TYPE = 3,
    PSBT_IN_REDEEM_SCRIPT = 4,
    PSBT_IN_WITNESS_SCRIPT = 5,
    PSBT_IN_BIP32_DERIVATION = 6,
    PSBT_IN_FINAL_SCRIPTSIG = 7,
    PSBT_IN_FINAL_SCRIPTWITNESS = 8,
    PSBT_IN_POR_COMMITMENT = 9,
    PSBT_IN_PROPRIETARY = 0xFC
} PSBT_INPUT_TYPES;

typedef enum _PSBT_OUTPUT_TYPES {
    PSBT_OUT_REDEEM_SCRIPT = 0,
    PSBT_OUT_WITNESS_SCRIPT = 1,
    PSBT_OUT_BIP32_DERIVATION = 2,
    PSBT_OUT_PROPRIETARY = 0xFC
} PSBT_OUTPUT_TYPES;


typedef union _PSBT_ELEMENT_TYPE{
    PSBT_GLOBAL_TYPES global;
    PSBT_INPUT_TYPES input;
    PSBT_OUTPUT_TYPES output;
} PSBT_ELEMENT_TYPE;

#define PSBT_ELEM_FLAG_UNKNOWN_TYPE  (1 << 0) // unknown or unparsed
#define PSBT_ELEM_FLAG_DIRTY        (1 << 1)  // parsed_elem changed

typedef struct _psbt_map_elem {
    struct const_buffer key;
    struct const_buffer value;
    uint32_t flag;
    PSBT_ELEMENT_TYPE type;
    union {
        void * elem;
        uint32_t data;
    } parsed;
} psbt_map_elem;

#define PSBT_GET_FLAG(elem, f)  ((elem->flag & f ) == f);
#define PSBT_SET_FLAG(elem, f, tf) \
    if(tf) { \
        elem->flag |= f; \
    } \
    else { \
        elem->flag &= ~f; \
    }

inline btc_bool psbt_map_elem_get_flag_unknown_type(const psbt_map_elem * elem)
{
    return PSBT_GET_FLAG(elem, PSBT_ELEM_FLAG_UNKNOWN_TYPE);
}

inline btc_bool psbt_map_elem_get_flag_dirty(const psbt_map_elem * elem)
{
    return PSBT_GET_FLAG(elem, PSBT_ELEM_FLAG_DIRTY);
}

inline void psbt_map_elem_set_flag_unknown_type(psbt_map_elem * elem, btc_bool unknown)
{
    PSBT_SET_FLAG(elem, PSBT_ELEM_FLAG_UNKNOWN_TYPE, unknown);
}

inline void psbt_map_elem_set_flag_dirty(psbt_map_elem * elem, btc_bool dirty)
{
    PSBT_SET_FLAG(elem, PSBT_ELEM_FLAG_DIRTY, dirty);
}


typedef struct _psbt {
    vector * global_data;
    vector * input_data;
    vector * output_data;
} psbt;

LIBBTC_API int psbt_deserialize( psbt * psbt, struct const_buffer *buffer);

LIBBTC_API int psbt_serialize( cstring * str, const psbt * psbt );

LIBBTC_API void psbt_init(psbt * psbt);

LIBBTC_API void psbt_reset(psbt * psbt);

LIBBTC_API uint32_t psbt_get_input_count(const psbt * psbt);

LIBBTC_API int psbt_check_for_sig(const psbt *psbt, uint32_t input_n, uint32_t * hashtype_out, char ** err_message);

LIBBTC_API int psbt_get_sighash(const psbt *psbt, uint32_t input_n, uint32_t hashtype, uint256 hash, char ** err_message);

LIBBTC_API int psbt_add_partial_sig(psbt *psbt, uint32_t input_n, uint8_t pubkey[33], uint8_t sig[65]);

// LIBBTC_API int psbt_sign(psbt *psbt, uint32_t input_n, const btc_key *privkey);

LIBBTC_END_DECL

#endif // __LIBBTC_PSBT_H__
