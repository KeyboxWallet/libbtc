#ifndef __LIBBTC_PSBT_H__
#define __LIBBTC_PSBT_H__

#include "btc.h"
#include "vector.h"
#include "serialize.h"

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

inline void psbt_map_elem_set_flag_unkown_type(psbt_map_elem * elem, btc_bool unknown)
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

LIBBTC_API psbt_map_elem * psbt_map_elem_new();

LIBBTC_API void psbt_map_elem_free(psbt_map_elem * elem);

LIBBTC_API int psbt_deserialize( psbt * psbt, struct const_buffer *buffer);

LIBBTC_API int psbt_serialize( cstring * str, const psbt * psbt );

LIBBTC_API void psbt_init(psbt * psbt);

LIBBTC_API void psbt_reset(psbt * psbt);

LIBBTC_END_DECL

#endif // __LIBBTC_PSBT_H__