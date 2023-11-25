#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

void mac_keygen(const char* mackey_path) {

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
     * 1. 파일 경로 설정
    */
    char* key_file_path = NULL;
    int alloc_flag = 0;
    if(mackey_path) {
        size_t key_path_len = strlen(mackey_path);
        key_file_path = (char*)calloc(key_path_len+50, 1);
        alloc_flag = 1;

        strncpy(key_file_path, mackey_path, key_path_len);
        strcat(key_file_path, "/mac_key.mk");
    }
    else {
        key_file_path = "mac_key.mk";
    }


    /**
     * 2. mac 키 생성
    */
    if((ret = NS_generate_key(&keygenctx,(NT_OBJECT_PTR)&oKey))!=NRC_OK)
    {
        printf("NS_generate_key failed: %s\n",NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, "oKey");


    /**
     * 3. 키 파일 저장
    */
    FILE* key_file = fopen(key_file_path, "wb");
    if(key_file == NULL) {
        puts("failed to generate key file..");
        goto err;
    }

    fwrite(&oKey[1].type, sizeof(NT_ULONG), 1, key_file);
    fwrite(&oKey[1].ulValueLen, sizeof(NT_ULONG), 1, key_file);
    fwrite(oKey[1].pValue, oKey[1].ulValueLen, 1, key_file);
    fwrite(&oKey[1].bSensitive, sizeof(NT_BBOOL), 1, key_file);
    fwrite(&oKey[1].bAlloc, sizeof(NT_BBOOL), 1, key_file);
    fclose(key_file);

    puts("generate mac key file complete.");

    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, "key data");


err:
    NS_clear_object(&oKey,2);

    if(alloc_flag) free(key_file_path);
    

    // return ret;

}