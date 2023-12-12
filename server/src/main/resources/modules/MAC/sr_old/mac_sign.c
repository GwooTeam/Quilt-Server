#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

int mac_sign(const char* mackey_path, const char* data_path, const char* sign_path) {

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
     * 1. 경로 설정
     * 해시코드를 저장할 경로 설정
    */
    char* sign_file_path = NULL;
    int alloc_flag = 0;
    if(sign_path) {
        size_t sign_path_len = strlen(sign_path);
        sign_file_path = (char*)calloc(sign_path_len+50, 1);
        alloc_flag = 1;

        strncpy(sign_file_path, mackey_path, sign_path_len);
        strcat(sign_file_path, "/mac_sign.ms");
    }
    else {
        sign_file_path = "mac_sign.ms";
    }


    /**
     * 1. mac 키 추출
     * 파일로부터 mac 키를 가져옴
    */

    // NT_ULONG_PTR attr_type = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    // NT_ULONG_PTR attr_ValLen = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    // NT_BBOOL* attr_bSensitive = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);
    // NT_BBOOL* attr_bAlloc = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);

    FILE* key_file = fopen(mackey_path, "rb");
    if(key_file == NULL) {
        puts("failed to open mac key file..");
        goto err;
    }

    // 데이터 읽기
    // fread(attr_type, sizeof(NT_ULONG), 1, key_file);
    // fread(attr_ValLen, sizeof(NT_ULONG), 1, key_file);
    NT_VOID_PTR attr_pValue = (NT_VOID_PTR)calloc(32, 1);

    fread(attr_pValue, 32, 1, key_file);
    // fread(attr_bSensitive, sizeof(NT_BBOOL), 1, key_file);
    // fread(attr_bAlloc, sizeof(NT_BBOOL), 1, key_file);

    // 오브젝트에 데이터 복사
    oKey[1].type = NAT_VALUE;
    oKey[1].ulValueLen = 32;

    oKey[1].pValue = (NT_VOID_PTR)calloc(32, 1);
    memcpy(oKey[1].pValue, attr_pValue, 32);
    
    oKey[1].bSensitive = TRUE;
    oKey[1].bAlloc = TRUE;

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "mac key");




    /**
     * 2. 데이터 추출
     * 파일로부터 해싱할 데이터를 가져옴
    */

    FILE* data_file = fopen(data_path, "rb");
    if(data_file == NULL) {
        puts("failed to open plain file..");
        goto err;
    }

    // 파일 크기 계산
    NT_ULONG data_file_size;
    // NT_ULONG padding;

    fseek(data_file, 0, SEEK_END);
    data_file_size = ftell(data_file);
    fseek(data_file, 0, SEEK_SET);

    // padding = 16 - (data_file_size % 16);
    // printf("plain_file_size: %d\n", data_file_size);
    // printf("padding: %d\n", padding);

    // 데이터 읽어오기
    NT_VOID_PTR plainData = (NT_VOID_PTR)calloc(data_file_size, 1);
    fread(plainData, data_file_size, 1, data_file);

    // char* tmpBuf = (char*)malloc(padding); 
    // int i;
    // for(i=0; i<padding; i++) {
    //     tmpBuf[i] = '\0';
    // }

    // strcat((char*)plainData, tmpBuf);

    // oData에 할당
    oData[1].pValue = plainData;
    oData[1].ulValueLen = data_file_size;

    // check oData
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, (NT_BYTE_PTR) "source data");


    ////


    // NT_BYTE DataBuf[32760] = { 0, };
    // memset(DataBuf, 'X', 255);
    // oData[1].pValue = DataBuf;
    // oData[1].ulValueLen = 255;
   
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, "key data");
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, "original data");


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
    FILE* sign_file;
    puts("generate sign file..");
    printf("sign_file_path = %s\n", sign_file_path);
    sign_file = fopen(sign_file_path, "wb");
    if(sign_file == NULL) {
        printf("failed to generate sign file.\n");
        goto err;
    }

    // fwrite(&oMacData[1].type, sizeof(NT_ULONG), 1, sign_file);
    // fwrite(&oMacData[1].ulValueLen, sizeof(NT_ULONG), 1, sign_file);
    fwrite(oMacData[1].pValue, oMacData[1].ulValueLen, 1, sign_file);
    // fwrite(&oMacData[1].bSensitive, sizeof(NT_BBOOL), 1, sign_file);
    // fwrite(&oMacData[1].bAlloc, sizeof(NT_BBOOL), 1, sign_file);
    fclose(sign_file);
    puts("complete to generate data sign file.");

    // printf("mac sign type: %d\n", oMacData[1].type);
    // printf("mac sign valLen: %d\n", oMacData[1].ulValueLen);
    // printf("mac sign bSense: %d\n", oMacData[1].bSensitive);
    // printf("mac sign bAlloc: %d\n", oMacData[1].bAlloc);

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

    if(alloc_flag) free(sign_file_path);
    // free(attr_type);
    // free(attr_ValLen);
    free(attr_pValue);
    // free(attr_bSensitive);
    // free(attr_bAlloc);

    return exit_code;

    // return ret;

}
