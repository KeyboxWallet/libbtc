#include <btc/psbt.h>
#include <btc/tx.h>
#include <btc/memory.h>

extern inline btc_bool psbt_map_elem_get_flag_unknown_type(const psbt_map_elem * elem);
extern inline btc_bool psbt_map_elem_get_flag_dirty(const psbt_map_elem * elem);
extern inline void psbt_map_elem_set_flag_unkown_type(psbt_map_elem * elem, btc_bool unknown);
extern inline void psbt_map_elem_set_flag_dirty(psbt_map_elem * elem, btc_bool dirty);

static psbt_map_elem * psbt_map_elem_new()
{
    psbt_map_elem* elem;
    elem = btc_malloc(sizeof(psbt_map_elem));
    return elem;
}

static void psbt_global_map_elem_free(void *e)
{
    psbt_map_elem *elem = e;
    if( elem->parsed.elem ){
        if( elem->type.global == PSBT_GLOBAL_UNSIGNED_TX){
            btc_tx_free((btc_tx*)elem->parsed.elem);
        }
    }
    btc_free(elem);
}

static void psbt_input_map_elem_free(void *e)
{
    psbt_map_elem *elem = e;
    if( elem->parsed.elem ){
        if( elem->type.input == PSBT_IN_NON_WITNESS_UTXO){
            btc_tx_free((btc_tx*)elem->parsed.elem);
        }
        else if( elem->type.input == PSBT_IN_WITNESS_UTXO){
            btc_tx_out_free(elem->parsed.elem);
        }
    }
    btc_free(elem);
}

static void psbt_map_free(void *e)
{
    vector_free(e, true);
}


static int psbt_map_elem_deserialize( psbt_map_elem * elem, struct const_buffer * buffer )
{
    int ret;
    uint32_t len;
    if(! deser_varlen(&len, buffer) ){
        return false;
    }
    elem->key.len = len;
    elem->key.p = buffer->p;
    if( !deser_skip(buffer, elem->key.len)){
        return false;
    }
    if( !deser_varlen(&len, buffer)){
        return false;
    }
    elem->value.len = len;
    elem->value.p = buffer->p;
    if( !deser_skip(buffer, elem->value.len)){
        return false;
    }
    psbt_map_elem_set_flag_unkown_type(elem, true);
    psbt_map_elem_set_flag_dirty(elem, false);
    elem->parsed.elem = NULL;
    return true;
}

static int psbt_map_deserialize(vector * vector, struct const_buffer * buffer)
{
    if(buffer->len == 0){
        return false;
    }
    while( buffer->len > 0){
        if( *(char*)buffer->p ==0 ){
            deser_skip(buffer, 1);
            return true;
        }
        psbt_map_elem * elem = psbt_map_elem_new();
        if( !psbt_map_elem_deserialize(elem, buffer)){
            btc_free(elem);
            return false;
        }
        // avoid duplicate key
        for(size_t i=0; i<vector->len; i++){
            psbt_map_elem *va = vector->data[i];
            if( buffer_equal(&va->key, &elem->key)){
                btc_free(elem);
                return false;
            }
        }

        if( !vector_add(vector, elem)){
            btc_free(elem);
            return false;
        }
    }
    return true;
}


static int psbt_global_map_element_parse(psbt_map_elem *elem)
{
    size_t parsedSize;
    btc_tx * tx;
    if( !elem ){
        return false;
    }
    if( elem->key.len < 1){
        return false;
    }
    uint8_t type = ((uint8_t*)elem->key.p)[0];
    elem->type.global = type;
    switch (type){
        case PSBT_GLOBAL_UNSIGNED_TX:
        if( elem->key.len != 1){
            return false;
        }
        tx = btc_tx_new();
        if(! btc_tx_deserialize(elem->value.p, elem->value.len, tx, &parsedSize, false)){
            return false;
        }
        if( parsedSize != elem->value.len){
            return false;
        }
        elem->parsed.elem = tx;
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
        default:
        break;
    }
    return true;
}


static int psbt_input_map_element_parse(psbt_map_elem *elem)
{
    size_t parsedSize;
    btc_tx * tx;
    btc_tx_out * out;
    struct const_buffer localBuf;
    if( !elem ){
        return false;
    }
    if( elem->key.len == 0){
        return elem->value.len == 0;
    }
    uint8_t type = ((uint8_t*)elem->key.p)[0];
    elem->type.input = type;
    switch (type){
    case PSBT_IN_NON_WITNESS_UTXO:
        if( elem->key.len != 1){
            return false;
        }
        tx = btc_tx_new();
        if(! btc_tx_deserialize(elem->value.p, elem->value.len, tx, &parsedSize, true)){
            btc_tx_free(tx);
            return false;
        }
        if( parsedSize != elem->value.len){
            btc_tx_free(tx);
            return false;
        }
        elem->parsed.elem = tx;
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_IN_WITNESS_UTXO:
        if( elem->key.len != 1){
            return false;
        }
        out = btc_tx_out_new();
        localBuf.p = elem->value.p;
        localBuf.len = elem->value.len;
        if( !btc_tx_out_deserialize(out, &localBuf)){
            btc_tx_out_free(out);
            return false;
        }
        elem->parsed.elem = out;
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_IN_PARTIAL_SIG:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_IN_SIGHASH_TYPE:
        if(elem->key.len != 1){
            return false;
        }
        if(elem->value.len != 4){
            return false;
        }
        memcpy(&elem->parsed.data, elem->value.p, 4);
        elem->parsed.data = le32toh(elem->parsed.data);
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_IN_REDEEM_SCRIPT:
    case PSBT_IN_WITNESS_SCRIPT:
    case PSBT_IN_FINAL_SCRIPTSIG:
    case PSBT_IN_FINAL_SCRIPTWITNESS:
    case PSBT_IN_POR_COMMITMENT:
        if(elem->key.len != 1){
            return false;
        }
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_IN_BIP32_DERIVATION:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    default:
        break;
    }
    return true;
}

static int psbt_output_map_element_parse(psbt_map_elem *elem)
{
    size_t parsedSize;
    btc_tx * tx;
    btc_tx_out * out;
    struct const_buffer localBuf;
    if( !elem ){
        return false;
    }
    if( elem->key.len < 1){
        return false;
    }
    uint8_t type = ((uint8_t*)elem->key.p)[0];
    elem->type.output = type;
    switch (type){
    case PSBT_OUT_REDEEM_SCRIPT:
    case PSBT_OUT_WITNESS_SCRIPT:
        if( elem->key.len != 1){
            return false;
        }
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    case PSBT_OUT_BIP32_DERIVATION:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unkown_type(elem, false);
        break;
    default:
        break;
    }
    return true;
}

int psbt_deserialize( psbt * psbt, struct const_buffer *buffer)
{
    uint32_t flag;
    uint8_t sep;
    size_t i,j;
    if( !deser_u32(&flag, buffer)){
        return false;
    }
    if( flag != 0x74627370){ // psbt in little endian
        return false;
    }
    if( !deser_bytes(&sep, buffer, 1)){
        return false;
    }
    if( sep != 0xff){
        return false;
    }
    psbt->global_data = vector_new(2, psbt_global_map_elem_free);
    if( !psbt_map_deserialize(psbt->global_data, buffer)){
        return false;
    }
    btc_tx * tx = NULL;
    for(i=0; i< psbt->global_data->len; i++){
        psbt_map_elem * elem = vector_idx(psbt->global_data,i);
        if(!psbt_global_map_element_parse(elem)){
            return false;
        }
        if( elem->type.global == PSBT_GLOBAL_UNSIGNED_TX ){
            tx = elem->parsed.elem;
        }
    }
    if(!tx){
        return false;
    }
    if( btc_tx_has_scriptSig(tx)){
        return false;
    }
    size_t vin_len = tx->vin->len;
    size_t vout_len = tx->vout->len;
    psbt->input_data = vector_new(vin_len, psbt_map_free);
    psbt->output_data = vector_new(vout_len, psbt_map_free);
    for(i=0; i<vin_len; i++){
        vector * in = vector_new(4, psbt_input_map_elem_free);
        if( !psbt_map_deserialize(in, buffer) ){
            vector_free(in, true);
            return false;
        }
        for(j=0; j<in->len; j++){
            if( !psbt_input_map_element_parse(vector_idx(in,j))){
                vector_free(in, true);
                return false;
            }
        }
        vector_add(psbt->input_data, in);
    }
    for(i=0; i<vout_len; i++){
        vector * out = vector_new(4, free);
        if( !psbt_map_deserialize(out, buffer) ){
            vector_free(out, true);
            return false;
        }
        for(j=0; j<out->len; j++){
            if( !psbt_output_map_element_parse(vector_idx(out,j))){
                vector_free(out, true);
                return false;
            }
        }
        vector_add(psbt->output_data, out);
    }

    return true;
}

void psbt_init(psbt * psbt)
{
    psbt->global_data = NULL;
    psbt->input_data = NULL;
    psbt->output_data = NULL;
}

void psbt_reset(psbt * psbt)
{
    if(psbt->global_data){
        vector_free(psbt->global_data, true);
        psbt->global_data = NULL;
    }
    if(psbt->input_data){
        vector_free(psbt->input_data, true);
        psbt->input_data = NULL;
    }
    if(psbt->output_data){
        vector_free(psbt->output_data, true);
        psbt->output_data = NULL;
    }
}

static inline void ser_psbt_map_elem(cstring *str, psbt_map_elem * elem)
{
    ser_varlen(str, elem->key.len);
    ser_bytes(str, elem->key.p, elem->key.len);
    ser_varlen(str, elem->value.len);
    ser_bytes(str, elem->value.p, elem->value.len);
}

int psbt_serialize( cstring * str, const psbt * psbt )
{
    if( !str || !psbt || !psbt->global_data){
        return false;
    }
    size_t origin_len = str->len;

    cstr_append_buf(str, "psbt", 4);
    cstr_append_c(str, 0xFF);

    psbt_map_elem * elem;
    size_t i,j;
    vector * vec;
    for(i=0; i<psbt->global_data->len; i++){
        elem = vector_idx(psbt->global_data, i);
        if(!psbt_map_elem_get_flag_dirty(elem)){
            ser_psbt_map_elem(str, elem);
        }
        else{
            goto _reset_cstring;
        }
    }
    cstr_append_c(str, 0);
    if( psbt->input_data )
    for(i=0; i<psbt->input_data->len; i++){
        vec = vector_idx(psbt->input_data, i);
        for(j=0; j<vec->len; j++){
            elem = vector_idx(vec, j);
            if( psbt_map_elem_get_flag_dirty(elem)){
                // todo: 
                goto _reset_cstring;
            }
            else{
                ser_psbt_map_elem(str, elem);
            }
        }
        cstr_append_c(str, 0);
    }

    for(i=0; i<psbt->output_data->len; i++){
        vec = vector_idx(psbt->output_data, i);
        for(j=0; j<vec->len; j++){
            elem = vector_idx(vec, j);
            if( psbt_map_elem_get_flag_dirty(elem)){
                // todo: 
                goto _reset_cstring;
            }
            else{
                ser_psbt_map_elem(str, elem);
            }
        }
        cstr_append_c(str, 0);
    }


    return true;

_reset_cstring:
    str->len = origin_len;
    return false;
}