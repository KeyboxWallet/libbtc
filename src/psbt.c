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


#include <btc/psbt.h>
#include <btc/tx.h>
#include <btc/memory.h>

extern inline btc_bool psbt_map_elem_get_flag_unknown_type(const psbt_map_elem * elem);
extern inline btc_bool psbt_map_elem_get_flag_dirty(const psbt_map_elem * elem);
extern inline void psbt_map_elem_set_flag_unknown_type(psbt_map_elem * elem, btc_bool unknown);
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
        else if( elem->type.input == PSBT_IN_PARTIAL_SIG){
            if(psbt_map_elem_get_flag_dirty(elem)){
                btc_free(elem->parsed.elem);
            }
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
    psbt_map_elem_set_flag_unknown_type(elem, true);
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
        psbt_map_elem_set_flag_unknown_type(elem, false);
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
        psbt_map_elem_set_flag_unknown_type(elem, false);
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
        psbt_map_elem_set_flag_unknown_type(elem, false);
        break;
    case PSBT_IN_PARTIAL_SIG:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unknown_type(elem, false);
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
        psbt_map_elem_set_flag_unknown_type(elem, false);
        break;
    case PSBT_IN_REDEEM_SCRIPT:
    case PSBT_IN_WITNESS_SCRIPT:
    case PSBT_IN_FINAL_SCRIPTSIG:
    case PSBT_IN_FINAL_SCRIPTWITNESS:
    case PSBT_IN_POR_COMMITMENT:
        if(elem->key.len != 1){
            return false;
        }
        psbt_map_elem_set_flag_unknown_type(elem, false);
        break;
    case PSBT_IN_BIP32_DERIVATION:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unknown_type(elem, false);
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
        psbt_map_elem_set_flag_unknown_type(elem, false);
        break;
    case PSBT_OUT_BIP32_DERIVATION:
        if(elem->key.len != 34 && elem->key.len != 66){
            return false;
        }
        psbt_map_elem_set_flag_unknown_type(elem, false);
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
                if( elem->type.input == PSBT_IN_PARTIAL_SIG){
                    ser_varlen(str, 33);
                    ser_bytes(str, elem->parsed.elem, 33);
                    ser_varlen(str, 65);
                    ser_bytes(str, (uint8_t*)elem->parsed.elem+33, 65);
                }
                else 
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


static btc_tx * get_unsigned_tx(const psbt * psbt)
{
    btc_tx * ret = NULL;
    size_t i;
    for(i=0; i<psbt->global_data->len; i++ ){
        psbt_map_elem * elem = vector_idx(psbt->global_data, i);
        if( elem->type.global == PSBT_GLOBAL_UNSIGNED_TX && !psbt_map_elem_get_flag_unknown_type(elem)){
            ret = elem->parsed.elem;
        }
    }
    return ret;
}

static btc_bool checkScriptPubkeyMatch(cstring *script, const uint160 targetHash)
{
    if( !script ){
        return false;
    }
    uint160 scriptHash;
    if( !btc_script_get_scripthash(script, scriptHash)){
        return false;
    }
    return memcmp(scriptHash, targetHash, 20) == 0;
}

int psbt_check_for_sig(const psbt *psbt, uint32_t input_n, uint32_t * hashtype_out, char ** err_message)
{
    #define SET_ERR_MSG_AND_RET(msg) { if(err_message) *err_message = #msg ; return false; }

    if( !psbt || !psbt->global_data || !psbt->input_data ) SET_ERR_MSG_AND_RET("invalid psbt");
    if( psbt->input_data->len <= input_n ) SET_ERR_MSG_AND_RET("input_n too large");
    btc_tx * tx = get_unsigned_tx(psbt);
    if( !tx ) SET_ERR_MSG_AND_RET("get unsigned transaction error");
    if( tx->vin->len <= input_n ) SET_ERR_MSG_AND_RET("input_n too large");
    btc_tx_in * tx_in = vector_idx(tx->vin, input_n);
    vector * input_map = vector_idx(psbt->input_data, input_n);
    size_t i;
    btc_tx * prev_tx;
    btc_tx_out * prev_tx_out = NULL;
    btc_tx_out * witness_utxo = NULL;
    uint256 txhash;
    uint8_t witness_version;
    uint8_t witness_program[40];
    int program_len = 0;
    cstring redeemStr;
    cstring witnessStr;
    redeemStr.len = 0;
    witnessStr.len = 0;
    vector *data_out = NULL;
    enum btc_tx_out_type tx_out_type;
    uint8_t * scriptPubkeyHash = NULL;
    * hashtype_out = SIGHASH_ALL;
    for(i=0; i<input_map->len; i++){
        psbt_map_elem * elem = vector_idx(input_map, i);
        btc_tx_in * vin = vector_idx(tx->vin, i);
        switch(elem->type.input){
        case PSBT_IN_NON_WITNESS_UTXO:
            prev_tx = elem->parsed.elem;
            btc_tx_hash(prev_tx, txhash);
            if(memcmp(txhash, tx_in->prevout.hash, 32) != 0){
                SET_ERR_MSG_AND_RET("non_witness_utxo txid mismatch");
            }
            prev_tx_out = vector_idx(prev_tx->vout, vin->prevout.n);
            break;
        case PSBT_IN_WITNESS_UTXO:
            witness_utxo = elem->parsed.elem;
            break;
        case PSBT_IN_REDEEM_SCRIPT:
            redeemStr.str = (char*)elem->value.p;
            redeemStr.len = elem->value.len;
            break;
        case PSBT_IN_WITNESS_SCRIPT:
            witnessStr.str = (char*)elem->value.p;
            witnessStr.len = elem->value.len;
            break;
        case PSBT_IN_SIGHASH_TYPE:
            *hashtype_out = elem->parsed.data;
            break;
        }
    }
    if( redeemStr.len != 0 ){
        if( prev_tx_out && witness_utxo ){
            SET_ERR_MSG_AND_RET("witness_utxo and non witness utxo coexist.");
        }
        if( prev_tx_out || witness_utxo ){
            cstring *scriptPubkey;
            if( prev_tx_out ) {
                scriptPubkey  = prev_tx_out->script_pubkey;
            }
            else if(witness_utxo) {
                scriptPubkey = witness_utxo->script_pubkey;
            }
            data_out = vector_new(2, free);
            tx_out_type = btc_script_classify(scriptPubkey, data_out);
            if (tx_out_type != BTC_TX_SCRIPTHASH){
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("redeem Script without script hash type");
            }
            if (!checkScriptPubkeyMatch(&redeemStr, vector_idx(data_out,0))){
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("redeem script with different script hash.");
            }
            vector_free(data_out, true);

            if( witness_utxo ){
                if(!btc_script_is_witnessprogram(&redeemStr, &witness_version,witness_program, &program_len ))
                    SET_ERR_MSG_AND_RET("wintess_utxo with non witness signature(p2sh wrapped)")
            }
        }
        data_out = vector_new(2, free);
        tx_out_type = btc_script_classify(&redeemStr, data_out);
        if( tx_out_type == BTC_TX_WITNESS_V0_SCRIPTHASH){
            if( witnessStr.len != 0){
                uint256 hash;
                sha256_Raw((uint8_t*)witnessStr.str, witnessStr.len, hash);
                if( memcmp(vector_idx(data_out,0), hash, 32) != 0){
                    vector_free(data_out, true);
                    SET_ERR_MSG_AND_RET("witness script not match hash in redeem script")
                }
            }
            else
            {
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("witness script hash redeemp script need witness script");
            }
        }
        vector_free(data_out, true);
    }
    else {
        if( witness_utxo ){
            if(!btc_script_is_witnessprogram(witness_utxo->script_pubkey, &witness_version, witness_program, &program_len))
                SET_ERR_MSG_AND_RET("witness_utxo with non witness signature");
        }
    }

    return true;
}


int psbt_get_sighash(const psbt *psbt, uint32_t input_n, uint32_t hash_type, uint256 hash, char ** err_message)
{
    #define SET_ERR_MSG_AND_RET(msg) { if(err_message) *err_message = #msg ; return false; }

    if( !psbt || !psbt->global_data || !psbt->input_data ) SET_ERR_MSG_AND_RET("invalid psbt");
    if( psbt->input_data->len <= input_n ) SET_ERR_MSG_AND_RET("input_n too large");
    btc_tx * tx = get_unsigned_tx(psbt);
    if( !tx ) SET_ERR_MSG_AND_RET("get unsigned transaction error");
    if( tx->vin->len <= input_n ) SET_ERR_MSG_AND_RET("input_n too large");
    btc_tx_in * tx_in = vector_idx(tx->vin, input_n);
    vector * input_map = vector_idx(psbt->input_data, input_n);
    size_t i;
    btc_tx * prev_tx;
    btc_tx_out * prev_tx_out = NULL;
    btc_tx_out * witness_utxo = NULL;
    uint256 txhash;
    uint8_t witness_version;
    uint8_t witness_program[40];
    int program_len = 0;
    cstring redeemStr;
    cstring witnessStr;
    cstring *fromPubkey = NULL;
    redeemStr.len = 0;
    witnessStr.len = 0;
    vector *data_out = NULL;
    enum btc_tx_out_type tx_out_type;
    uint8_t * scriptPubkeyHash = NULL;
    for(i=0; i<input_map->len; i++){
        psbt_map_elem * elem = vector_idx(input_map, i);
        btc_tx_in * vin = vector_idx(tx->vin, i);
        switch(elem->type.input){
        case PSBT_IN_NON_WITNESS_UTXO:
            prev_tx = elem->parsed.elem;
            btc_tx_hash(prev_tx, txhash);
            if(memcmp(txhash, tx_in->prevout.hash, 32) != 0){
                SET_ERR_MSG_AND_RET("non_witness_utxo txid mismatch");
            }
            prev_tx_out = vector_idx(prev_tx->vout, vin->prevout.n);
            break;
        case PSBT_IN_WITNESS_UTXO:
            witness_utxo = elem->parsed.elem;
            break;
        case PSBT_IN_REDEEM_SCRIPT:
            redeemStr.str = (char*)elem->value.p;
            redeemStr.len = elem->value.len;
            break;
        case PSBT_IN_WITNESS_SCRIPT:
            witnessStr.str = (char*)elem->value.p;
            witnessStr.len = elem->value.len;
            break;
        case PSBT_IN_SIGHASH_TYPE:
            //*hashtype_out = elem->parsed.data;
            if(elem->parsed.data != hash_type)
                SET_ERR_MSG_AND_RET("hash type missmatch")
            break;
        }
    }
    if( redeemStr.len != 0 ){
        if( prev_tx_out && witness_utxo ){
            SET_ERR_MSG_AND_RET("witness_utxo and non witness utxo coexist.");
        }
        if( prev_tx_out || witness_utxo ){
            cstring *scriptPubkey;
            if( prev_tx_out ) {
                scriptPubkey  = prev_tx_out->script_pubkey;
            }
            else if(witness_utxo) {
                scriptPubkey = witness_utxo->script_pubkey;
            }
            data_out = vector_new(2, free);
            tx_out_type = btc_script_classify(scriptPubkey, data_out);
            if (tx_out_type != BTC_TX_SCRIPTHASH){
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("redeem Script without script hash type");
            }
            if (!checkScriptPubkeyMatch(&redeemStr, vector_idx(data_out,0))){
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("redeem script with different script hash.");
            }
            vector_free(data_out, true);

            if( witness_utxo ){
                if(!btc_script_is_witnessprogram(&redeemStr, &witness_version,witness_program, &program_len ))
                    SET_ERR_MSG_AND_RET("wintess_utxo with non witness signature(p2sh wrapped)")
            }
        }
        data_out = vector_new(2, free);
        tx_out_type = btc_script_classify(&redeemStr, data_out);
        if( tx_out_type == BTC_TX_WITNESS_V0_SCRIPTHASH){
            if( witnessStr.len != 0){
                uint256 hash;
                sha256_Raw((uint8_t*)witnessStr.str, witnessStr.len, hash);
                if( memcmp(vector_idx(data_out,0), hash, 32) != 0){
                    vector_free(data_out, true);
                    SET_ERR_MSG_AND_RET("witness script not match hash in redeem script")
                }
            }
            else
            {
                vector_free(data_out, true);
                SET_ERR_MSG_AND_RET("witness script hash redeemp script need witness script");
            }
        }
        vector_free(data_out, true);
    }
    else {
        if( witness_utxo ){
            if(!btc_script_is_witnessprogram(witness_utxo->script_pubkey, &witness_version, witness_program, &program_len))
                SET_ERR_MSG_AND_RET("witness_utxo with non witness signature");
        }
    }

    if( prev_tx_out ){
        if(redeemStr.len != 0){
            fromPubkey = &redeemStr;
        }
        else{
            fromPubkey = prev_tx_out->script_pubkey;
        }
        return btc_tx_sighash(tx, fromPubkey, input_n, hash_type, prev_tx_out->value, SIGVERSION_BASE, hash);
    }
    else if(witness_utxo){
        if(redeemStr.len != 0){
            fromPubkey = &redeemStr;
        }
        else {
            fromPubkey = witness_utxo->script_pubkey;
        }
        data_out = vector_new(2, free);
        tx_out_type = btc_script_classify(fromPubkey, data_out);
        int ret;
        cstring * signPubkey = NULL;
        if( tx_out_type == BTC_TX_WITNESS_V0_PUBKEYHASH) {
            signPubkey = cstr_new_sz(0);
            ret = btc_script_build_p2pkh(signPubkey, vector_idx(data_out,0));
            ret = btc_tx_sighash(tx, signPubkey, input_n, hash_type, witness_utxo->value, SIGVERSION_WITNESS_V0 ,hash);
            cstr_free(signPubkey, true);
        }
        else if( tx_out_type == BTC_TX_WITNESS_V0_SCRIPTHASH ){
            ret = btc_tx_sighash(tx, &witnessStr, input_n, hash_type, witness_utxo->value, SIGVERSION_WITNESS_V0 ,hash);
        }
        else {
            vector_free(data_out, true);
            SET_ERR_MSG_AND_RET("unknown witness script type.");
        }
        vector_free(data_out, true);
        return ret;
    }
    else{
        SET_ERR_MSG_AND_RET("neither non_witness_utxo nor witness_utxo is provided.");
    }

    return true;
}

int psbt_add_partial_sig(psbt *psbt, uint32_t input_n, uint8_t pubkey[33], uint8_t sig[65])
{
    if( !psbt || !psbt->global_data || !psbt->input_data ) return false;
    if( psbt->input_data->len <= input_n ) return false;
    if( !pubkey || !sig ) return false;
    psbt_map_elem * elem = psbt_map_elem_new();
    elem->type.input = PSBT_IN_PARTIAL_SIG;
    psbt_map_elem_set_flag_dirty(elem, true);
    elem->parsed.elem = btc_malloc(33+65);
    memcpy(elem->parsed.elem, pubkey, 33);
    memcpy((uint8_t*)elem->parsed.elem + 33, sig, 65);
    vector_add(vector_idx(psbt->input_data, input_n), elem);
    return true;
}
