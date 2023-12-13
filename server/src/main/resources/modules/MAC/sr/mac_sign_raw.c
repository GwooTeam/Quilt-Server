#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

#include "quilt_api.h"

int mac_sign_raw(const char* mkey_val, const char* data_val) {

    int exit_code = 1;
    
    NT_ULONG skey_type = NOB_SECRET_KEY;
    NT_ULONG data_type = NOB_DATA;
    NT_ULONG mac_alg = NOB_CTX_AES_CMAC;

    NT_CONTEXT macctx = {
        {NAT_OBJECT_TYPE, &mac_alg, sizeof(mac_alg), FALSE, FALSE}
    };

    NT_OBJECT oKey = {
        {NAT_OBJECT_TYPE, &skey_type, sizeof(skey_type), FALSE, FALSE},
        {NAT_VALUE, NULL, NMC_AES256_KEY_BYTE_LEN, TRUE, FALSE}
    };

    NT_OBJECT oData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE},
    };
    
    NT_OBJECT oMacData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, NMC_AES_BLOCK_BYTE_LEN, TRUE, FALSE}
    };

    /* Default */
    NT_ULONG ulMacLen = 16;

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
     * 1. mac 키 추출
     * 파일로부터 mac 키를 가져옴
    */

    size_t mkey_size = strlen(mkey_val) / 2;
    // printf("puk_len: %d\n", puk_len);
    oKey[1].type = NAT_VALUE;

    oKey[1].pValue = (NT_VOID_PTR)calloc(32, 1);
    hexToByte(mkey_val, (unsigned char*)oKey[1].pValue, 32);

    oKey[1].ulValueLen = mkey_size;
    oKey[1].bAlloc = TRUE;
    oKey[1].bSensitive = TRUE;

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "mac key");

    /**
     * 2. 데이터 추출
     * 파일로부터 해싱할 데이터를 가져옴
    */

    // 파일 크기 계산
    NT_ULONG data_val_len = strlen(data_val);
    oData[1].pValue = (NT_VOID_PTR)calloc(data_val_len, 1);
    strncpy(oData[1].pValue, data_val, data_val_len);

    oData[1].ulValueLen = data_val_len;
    oData[1].bSensitive = FALSE;
    oData[1].bAlloc = FALSE;

    puts("mmodule - success to read origin data");
    // check oData
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, (NT_BYTE_PTR) "source data");


    /**
     * 3. MAC 생성 초기화 (sign_init)
    */

    /*싱글파트 맥 생성*/
    if((ret=NS_sign_init(&macctx, (NT_OBJECT_PTR)&oKey))!= NRC_OK ){
        printf("NS_sign_init failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }


    /**
     * 4. MAC 생성 (sign)
    */
    if((ret=NS_sign(&macctx, (NT_OBJECT_PTR)&oData,
        (NT_OBJECT_PTR)&oMacData))!= NRC_OK ) {
        printf("NS_sign failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oMacData[1].pValue, oMacData[1].ulValueLen, "mac data[all]");


    /**
     * 5. MAC 파일 생성
    */

    printVal("hash=", oMacData[1].pValue, oMacData[1].ulValueLen);

    exit_code = 0;


    // /*싱글파트 맥 검증*/
    // if((ret=NS_verify_init(&macctx, (NT_OBJECT_PTR)&oKey))!= NRC_OK ){
    //     printf("NS_verify_init failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // if((ret=NS_verify(&macctx, (NT_OBJECT_PTR)&oData,
    //     (NT_OBJECT_PTR)&oMacData))!= NRC_OK ) {
    //     printf("NS_verify failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }
    // else {
    //     printf("success verify mac[all]\n");
    // }

    // NS_clear_object(&oMacData,2);

    // /*멀티파트 맥 생성*/
    // if((ret=NS_sign_init(&macctx, (NT_OBJECT_PTR)&oKey))!= NRC_OK ){
    //     printf("NS_sign_init failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // if((ret=NS_sign_update(&macctx, (NT_OBJECT_PTR)&oData))!= NRC_OK ) {
    //     printf("NS_sign_update failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // oMacData[1].pValue = NULL;
    // if((ret=NS_sign_final(&macctx, (NT_OBJECT_PTR)&oMacData))!= NRC_OK ) {
    //     printf("NS_sign_final failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // NS_hex_dump(oMacData[1].pValue, oMacData[1].ulValueLen, "mac data");

    // /*멀티파트 맥 검증*/
    // if((ret=NS_verify_init(&macctx, (NT_OBJECT_PTR)&oKey))!= NRC_OK ){
    //     printf("NS_verify_init failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // if((ret=NS_verify_update(&macctx, (NT_OBJECT_PTR)&oData))!= NRC_OK ) {
    //     printf("NS_verify_update failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }

    // if((ret=NS_verify_final(&macctx, (NT_OBJECT_PTR)&oMacData))!= NRC_OK ) {
    //     printf("NS_verify_final failed: %s\n",NS_get_errmsg(ret));
    //     goto err;
    // }
    // else {
    //     printf("success to verify mac\n");
    // }

    // NS_clear_object(&oMacData,2);

    // /* Be careful how we should free mems in each case. */
    // if(kg_type == NOB_CTX_SYM_KEY_GEN) free(oKey[1].pValue); /* alloced outside dll */
    // else NS_clear_object(&oKey,2); /* alloced inside dll */


err:
    NS_clear_object(&oKey,2);
    NS_clear_object(&oMacData,2);

    return exit_code;

    // return ret;

}
