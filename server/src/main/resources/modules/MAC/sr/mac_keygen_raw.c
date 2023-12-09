#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

#include "quilt_api.h"

void mac_keygen_raw() {

    NT_ULONG kg_type = NOB_CTX_AES_KEY_GEN; // NOB_CTX_SYM_KEY_GEN;
    NT_ULONG skey_type = NOB_SECRET_KEY;
    NT_ULONG data_type = NOB_DATA;

    NT_ULONG mac_alg = NOB_CTX_AES_CMAC;

    NT_CONTEXT keygenctx = {
        {NAT_OBJECT_TYPE, &kg_type, sizeof(kg_type), FALSE, FALSE},
    };

    NT_CONTEXT macctx = {
        {NAT_OBJECT_TYPE, &mac_alg, sizeof(mac_alg), FALSE, FALSE}
    };

    /* Default */
    NT_ULONG ulMacLen = 16;

    NT_OBJECT oKey = {
        {NAT_OBJECT_TYPE, &skey_type, sizeof(skey_type), FALSE, FALSE},
        {NAT_VALUE, NULL, NMC_AES256_KEY_BYTE_LEN, TRUE, FALSE}
    };

    NT_RV ret;

    // oMacData[1].ulValueLen=NMC_AES_BLOCK_BYTE_LEN;
    // kg_type = NOB_CTX_AES_KEY_GEN;
    // oKey[1].pValue = NULL;
    // oKey[1].ulValueLen=NMC_AES128_KEY_BYTE_LEN;

    /**
     * Step 0. 모드 변경
     * 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL);
    // printf("current status = %d\n", NS_get_state());


    /**
     * 1. mac 키 생성
    */
    if((ret = NS_generate_key(&keygenctx,(NT_OBJECT_PTR)&oKey))!=NRC_OK)
    {
        printf("NS_generate_key failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, "oKey");


    /**
     * 2. 키 출력
    */

    printVal("mkey=", oKey[1].pValue, oKey[1].ulValueLen);

    // printf("mac key type: %d\n", oKey[1].type);
    // printf("mac key valLen: %d\n", oKey[1].ulValueLen);
    // printf("mac key bSensitive: %d\n", oKey[1].bSensitive);
    // printf("mac key bAlloc: %d\n", oKey[1].bAlloc);

    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, "key data");


err:
    NS_clear_object(&oKey,2);
    // return ret;

}