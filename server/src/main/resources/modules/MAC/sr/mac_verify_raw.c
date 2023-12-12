#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsc_api.h"

int mac_verify_raw(const char* mkey_val, const char* data_val, const char* sign_val) {

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


    /**
     * Step 0. 모드 변경
     * 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL);
    // printf("current status = %d\n", NS_get_state());


    /**
     * 1. mac 키 추출
     * 인자로 전달된 mac 키를 oKey에 저장.
    */

    size_t mkey_size = strlen(mkey_val) / 2; // mac key length is 32 byte
    if(mkey_size != 32) {
        fprintf(stderr, "mmodule - mac key length is not correct.");
        goto err;
    }
    // printf("puk_len: %d\n", puk_len);
    oKey[1].type = NAT_VALUE;

    oKey[1].pValue = (NT_VOID_PTR)calloc(32, 1); // allocate 32 byte
    hexToByte(mkey_val, (unsigned char*)oKey[1].pValue, 32);

    oKey[1].ulValueLen = mkey_size;
    oKey[1].bAlloc = TRUE;
    oKey[1].bSensitive = TRUE;

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "mac key");



    /**
     * 2. 원본 데이터 추출
     * 인자로 전달된 원본 코드를 oData에 저장.
     */

    // 파일 크기 계산
    NT_ULONG data_val_len = strlen(data_val);
    oData[1].pValue = (NT_VOID_PTR)calloc(data_val_len, 1);
    strncpy(oData[1].pValue, data_val, data_val_len);

    oData[1].ulValueLen = data_val_len;
    oData[1].bSensitive = FALSE;
    oData[1].bAlloc = FALSE;

    puts("mmodule - success to read origin data");

    // check oMacData
    // NS_hex_dump(oMacData[1].pValue, oMacData[1].ulValueLen, (NT_BYTE_PTR) "mac data");



    /**
     * 3. 해시코드 추출
     * 검증할 해시코드를 oMacData에 저장.
     */

    size_t sign_size = strlen(sign_val) / 2; // mac sign length is 16 byte
    if(sign_size != 16) {
        fprintf(stderr, "mmodule - sign size is not correct.");
        goto err;
    }
    // printf("puk_len: %d\n", puk_len);
    oMacData[1].type = NAT_VALUE;

    oMacData[1].pValue = (NT_VOID_PTR)calloc(16, 1); // allocate 16 byte
    hexToByte(sign_val, (unsigned char*)oMacData[1].pValue, 16);

    oMacData[1].ulValueLen = 16;
    oMacData[1].bAlloc = TRUE;
    oMacData[1].bSensitive = TRUE;

    // check oData
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, (NT_BYTE_PTR) "source data");
    

    /**
     * 4. mac 검증 수행
     */

    /*싱글파트 맥 검증*/
    if((ret=NS_verify_init(&macctx, (NT_OBJECT_PTR)&oKey))!= NRC_OK ){
        printf("NS_verify_init failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }

    if((ret=NS_verify(&macctx, (NT_OBJECT_PTR)&oData,
        (NT_OBJECT_PTR)&oMacData))!= NRC_OK ) {
        printf("NS_verify failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }
    else {
        printf("success verify mac\n");
    }

    exit_code = 0;


err:
    NS_clear_object(&oKey,2);
    NS_clear_object(&oMacData,2);
    NS_clear_object(&oData,2);

    return exit_code;

}
