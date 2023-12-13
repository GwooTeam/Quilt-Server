#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

/// @brief Kyber768 Standard

/// - security level: Level 3
/// - matrix computation: No
/// - symmetric primitive: SHA3
/// - randomized signing: No

/* kyber encrypt module */
void kyber_decapsulate(const char* prk_path, const char* capsule_path, const char* decap_path) {

    NT_ULONG enc_type = NOB_CTX_KYBER_KEM; /* type*/

    NT_ULONG prk_type = NOB_PRIVATE_KEY;  /* private-key*/
    NT_ULONG ss_type = NOB_SHARED_SECRET; /* shared secret*/
    NT_ULONG enc_data_type = NOB_DATA;    /* encrypted data type*/

    NT_OBJECT oPrivateKey = {
        {NAT_OBJECT_TYPE, &prk_type, sizeof(prk_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}};

    NT_CONTEXT kyberctx = {
        {NAT_OBJECT_TYPE, &enc_type, sizeof(enc_type), FALSE, FALSE},
        {NAT_KYBER_SECURITY_LEVEL, NULL, 0, FALSE, FALSE},
        {NAT_KYBER_IS_MATRIX_PRECOMPUTED, NULL, 0, FALSE, FALSE},
        {NAT_KYBER_SYMMETRIC_PRIMITIVE_TYPE, NULL, 0, FALSE, FALSE},
        {NAT_RANDOM_FUNCTION_TYPE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oEncryptedData = {
        {NAT_OBJECT_TYPE, &enc_data_type, sizeof(enc_data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oSharedSecret = {
        {NAT_OBJECT_TYPE, &ss_type, sizeof(ss_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}};

    NT_RV ret;


    // 디캡슐화한 데이터 저장 경로 설정
    char* decap_file_path = NULL;
    int alloc_flag = 0;
    if(decap_path) { // <입력한 경로 + 파일 이름>으로 파일 생성
        size_t data_path_len = strlen(capsule_path);
        decap_file_path = calloc(data_path_len+50, 1);
        alloc_flag = 1;

        strncpy(decap_file_path, decap_path, data_path_len);
        strcat(decap_file_path, "/kyber_sharedsecret.ssk");
    }
    else {
        decap_file_path = "kyber_sharedsecret.ssk";
    }

    // puts("check in kyber_decapsulate()");
    // printf("prk_path: %s\n", prk_path);
    // printf("capsule_path: %s\n", capsule_path);
    // printf("decap_path: %s\n", decap_path);

    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL_PQC);
    // printf("current status = %d\n", NS_get_state());


    /**
     * step 1. 디캡슐화에 쓸 개인키 추출
     * 파일로 저장된 개인키를 읽어서 oPrivateKey에 저장.
    */

    FILE* prk_file;
    prk_file = fopen(prk_path, "rb");

    if(prk_file == NULL) {
        puts("fail to open private key...");
        goto err;
    }
    puts("success to open prk file.");

    NT_ULONG_PTR attr_type = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_ULONG_PTR attr_ValLen = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_BBOOL* attr_bSensitive = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);
    NT_BBOOL* attr_bAlloc = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);

    fread(attr_type, sizeof(NT_ULONG), 1, prk_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, prk_file);

    NT_VOID_PTR attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);

    fread(attr_pValue, *attr_ValLen, 1, prk_file);
    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, prk_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, prk_file);
    fclose(prk_file);

    oPrivateKey[1].type = *attr_type;
    oPrivateKey[1].ulValueLen = *attr_ValLen;

    oPrivateKey[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oPrivateKey[1].pValue, attr_pValue, *attr_ValLen);
    
    oPrivateKey[1].bSensitive = *attr_bSensitive;
    oPrivateKey[1].bAlloc = *attr_bAlloc;

    // check private key
    // NS_hex_dump(oPrivateKey[1].pValue, oPrivateKey[1].ulValueLen, (NT_BYTE_PTR) "private key");


    /**
     * Step 2. 디캡슐화 초기작업 (init, 캡슐 데이터 읽어오기)
     */
    if ((ret = NS_decapsulate_init(&kyberctx,
                                   (NT_OBJECT_PTR)&oPrivateKey)) != NRC_OK)
    {
        printf("NS_decapsulate_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // 캡슐 데이터 읽어오기
    // printf("opening capsule file to decapsulate..\n");
    FILE* cap_file;
    // printf("capsule_path = %s\n", capsule_path);
    cap_file = fopen(capsule_path, "rb");
    if(cap_file == NULL) {
        printf("failed to open capsulated file\n");
        goto err;
    }

    // puts("read data from capsulated file..");
    memset(attr_type, 0, sizeof(NT_ULONG));
    // memset(attr_pValue, 0, *attr_ValLen);
    memset(attr_ValLen, 0, sizeof(NT_ULONG));
    memset(attr_bSensitive, 0, sizeof(NT_BBOOL));
    memset(attr_bAlloc, 0, sizeof(NT_BBOOL));
    free(attr_pValue);

    fread(attr_type, sizeof(NT_ULONG), 1, cap_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, cap_file);

    attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    fread(attr_pValue, *attr_ValLen, 1, cap_file);

    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, cap_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, cap_file);
    fclose(cap_file);
    printf("success to read capsulated file.\n");

    oEncryptedData[1].type = *attr_type;
    oEncryptedData[1].ulValueLen = *attr_ValLen;

    oEncryptedData[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oEncryptedData[1].pValue, attr_pValue, *attr_ValLen);

    oEncryptedData[1].bSensitive = *attr_bSensitive;
    oEncryptedData[1].bAlloc = *attr_bAlloc;


    /**
     * Step 3. 디캡슐화
     * NS_decapsulate() 호출 전에 반드시 NS_decapsulate_init()로 초기 작업을 수행해야 한다.
     */

    // printf("start decapsulating..\n");
    if ((ret = NS_decapsulate(&kyberctx,
                              (NT_OBJECT_PTR)&oEncryptedData, // (NT_OBJECT_PTR)&oEncryptedData
                              (NT_OBJECT_PTR)&oSharedSecret)) != NRC_OK)
    {
        printf("NS_decapsulate failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // printf("decapsulate done.\n");

    /* Print to ss1 */
    // NS_hex_dump(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, (NT_BYTE_PTR) "shared secret1");


    
    /**
     * step 4. 디캡슐화한 데이터를 파일로 저장.
    */

    FILE* decap_file;
    // puts("generate decapsulate data to file..");
    // printf("decap_file_path = %s\n", decap_file_path);
    decap_file = fopen(decap_file_path, "wb");
    if(decap_file == NULL) {
        printf("failed to generate decapsulated data file.\n");
        goto err;
    }

    fwrite(&oSharedSecret[1].type, sizeof(NT_ULONG), 1, decap_file);
    fwrite(&oSharedSecret[1].ulValueLen, sizeof(NT_ULONG), 1, decap_file);
    fwrite(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, 1, decap_file);
    fwrite(&oSharedSecret[1].bSensitive, sizeof(NT_BBOOL), 1, decap_file);
    fwrite(&oSharedSecret[1].bAlloc, sizeof(NT_BBOOL), 1, decap_file);
    fclose(decap_file);
    puts("generate decapsulated data file complete.");


err:
    NS_clear_object(&oPrivateKey, 2);
    NS_clear_object(&oEncryptedData, 2);
    NS_clear_object(&oSharedSecret, 2);

    if(alloc_flag) free(decap_file_path);

    if(attr_type) free(attr_type);
    if(attr_ValLen) free(attr_ValLen);
    if(attr_pValue) free(attr_pValue);
    if(attr_bSensitive) free(attr_bSensitive);
    if(attr_bAlloc) free(attr_bAlloc);

}