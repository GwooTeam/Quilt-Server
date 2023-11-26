#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "nsc_api.h"

int mac_verify(const char* mackey_path, const char* data_path, const char* sign_path) {

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
     * 파일로부터 mac 키를 가져옴
    */

    NT_ULONG_PTR attr_type = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_ULONG_PTR attr_ValLen = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_BBOOL* attr_bSensitive = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);
    NT_BBOOL* attr_bAlloc = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);

    FILE* key_file = fopen(mackey_path, "rb");
    if(key_file == NULL) {
        puts("failed to open mac key file..");
        goto err;
    }

    // 데이터 읽기
    fread(attr_type, sizeof(NT_ULONG), 1, key_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, key_file);
    NT_VOID_PTR attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);

    fread(attr_pValue, *attr_ValLen, 1, key_file);
    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, key_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, key_file);

    // 오브젝트에 데이터 복사
    oKey[1].type = *attr_type;
    oKey[1].ulValueLen = *attr_ValLen;

    oKey[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oKey[1].pValue, attr_pValue, *attr_ValLen);
    
    oKey[1].bSensitive = *attr_bSensitive;
    oKey[1].bAlloc = *attr_bAlloc;

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "mac key");



    /**
     * 2. mac 해시코드 추출
     * 검증할 해시코드를 파일로부터 읽어옴
     */

    FILE* sign_file = fopen(sign_path, "rb");
    if(sign_file == NULL) {
        puts("failed to open cipher file..");
        goto err;
    }

    // 데이터 담아둘 임시변수 초기화
    puts("read data from cipher file..");
    memset(attr_type, 0, sizeof(NT_ULONG));
    // memset(attr_pValue, 0, *attr_ValLen);
    memset(attr_ValLen, 0, sizeof(NT_ULONG));
    memset(attr_bSensitive, 0, sizeof(NT_BBOOL));
    memset(attr_bAlloc, 0, sizeof(NT_BBOOL));
    free(attr_pValue);

    // 해시코드 읽어오기
    fread(attr_type, sizeof(NT_ULONG), 1, sign_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, sign_file);

    attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    fread(attr_pValue, *attr_ValLen, 1, sign_file);

    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, sign_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, sign_file);
    fclose(sign_file);
    printf("success to read capsulated file.\n");

    // oEncryptedData에 할당
    oMacData[1].type = *attr_type;
    oMacData[1].ulValueLen = *attr_ValLen;

    oMacData[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oMacData[1].pValue, attr_pValue, *attr_ValLen);

    oMacData[1].bSensitive = *attr_bSensitive;
    oMacData[1].bAlloc = *attr_bAlloc;

    // check oMacData
    // NS_hex_dump(oMacData[1].pValue, oMacData[1].ulValueLen, (NT_BYTE_PTR) "mac data");



    /**
     * 3. 데이터 추출
     * 해싱 대상 데이터를 추출
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
        printf("success verify mac[all]\n");
    }

    exit_code = 0;


err:
    NS_clear_object(&oKey,2);
    NS_clear_object(&oMacData,2);
    NS_clear_object(&oData,2);

    free(attr_type);
    free(attr_ValLen);
    free(attr_pValue);
    free(attr_bSensitive);
    free(attr_bAlloc);

    return exit_code;

}
