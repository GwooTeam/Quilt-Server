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
void kyber_encapsulate(const char* puk_path, const char* result_path) {

    NT_ULONG enc_type = NOB_CTX_KYBER_KEM;            /* type*/

    NT_ULONG puk_type = NOB_PUBLIC_KEY;   /* public-key*/
    NT_ULONG ss_type = NOB_SHARED_SECRET; /* shared secret*/
    NT_ULONG enc_data_type = NOB_DATA;    /* encrypted data type*/

    NT_OBJECT oPublicKey = {
        {NAT_OBJECT_TYPE, &puk_type, sizeof(puk_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

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


    // 캡슐화한 데이터 저장 경로 설정
    char* capsule_file_path = NULL;
    char* ssk_file_path = NULL;
    int alloc_flag = 0;
    if(result_path) { // <입력한 경로 + 파일 이름>으로 파일 생성
        size_t result_path_len = strlen(result_path);
        capsule_file_path = calloc(result_path_len+50, 1);
        ssk_file_path = calloc(result_path_len+50, 1);
        alloc_flag = 1;

        strncpy(capsule_file_path, result_path, result_path_len);
        strncpy(ssk_file_path, result_path, result_path_len);
        strcat(capsule_file_path, "/kyber_encapsulated.cap");
        strcat(ssk_file_path, "/kyber_sharedSecret.ssk");
    }
    else {
        capsule_file_path = "kyber_encapsulated.cap";
        ssk_file_path = "kyber_sharedSecret.ssk";
    }

    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL_PQC);
    // printf("current status = %d\n", NS_get_state());


    /**
     * step 1. 캡슐화에 쓸 공개키 추출
     * 파일로 저장된 공개키를 읽어서 oPublicKey에 저장.
    */

    FILE* puk_file;
    puk_file = fopen(puk_path, "rb");
    if(puk_file == NULL) {
        puts("failed to open public key...");
        goto err;
    }

    NT_ULONG_PTR attr_type = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_ULONG_PTR attr_ValLen = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_BBOOL* attr_bSensitive = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);
    NT_BBOOL* attr_bAlloc = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);

    fread(attr_type, sizeof(NT_ULONG), 1, puk_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, puk_file);

    NT_VOID_PTR attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);

    fread(attr_pValue, *attr_ValLen, 1, puk_file);
    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, puk_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, puk_file);
    fclose(puk_file);

    oPublicKey[1].type = *attr_type;

    oPublicKey[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oPublicKey[1].pValue, attr_pValue, *attr_ValLen);
    
    oPublicKey[1].ulValueLen = *attr_ValLen;
    oPublicKey[1].bSensitive = *attr_bSensitive;
    oPublicKey[1].bAlloc = *attr_bAlloc;

    // check public key
    // NS_hex_dump(oPublicKey[1].pValue, oPublicKey[1].ulValueLen, (NT_BYTE_PTR) "public key");


    /**
     * Step 2. 캡슐화 초기작업
     */
    if ((ret = NS_encapsulate_init(&kyberctx, (NT_OBJECT_PTR)&oPublicKey)) != NRC_OK)
    {
        printf("NS_encapsulate_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }


    /**
     * Step 3. 캡슐화
     * NS_encapsulate 호출 전에 반드시 NS_encapsulate_init로 초기 작업을 수행해야 한다.
     */
    ret = NS_encapsulate(&kyberctx,
                         (NT_OBJECT_PTR)&oEncryptedData,
                         (NT_OBJECT_PTR)&oSharedSecret);
    if (ret != NRC_OK)
    {
        printf("NS_encapsulate failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oEncryptedData[1].pValue,
    //             oEncryptedData[1].ulValueLen, (NT_BYTE_PTR) "encrypted data");

    
    /**
     * step 4. 캡슐화한 데이터를 파일로 저장.
    */
    FILE* capsule_file;
    // puts("into capsulated data to file..");
    // printf("capsule_file_path = %s\n", capsule_file_path);
    capsule_file = fopen(capsule_file_path, "wb");
    if(capsule_file == NULL) {
        printf("failed to generate data capsule file.\n");
        goto err;
    }

    fwrite(&oEncryptedData[1].type, sizeof(NT_ULONG), 1, capsule_file);
    fwrite(&oEncryptedData[1].ulValueLen, sizeof(NT_ULONG), 1, capsule_file);
    fwrite(oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, 1, capsule_file);
    fwrite(&oEncryptedData[1].bSensitive, sizeof(NT_BBOOL), 1, capsule_file);
    fwrite(&oEncryptedData[1].bAlloc, sizeof(NT_BBOOL), 1, capsule_file);
    fclose(capsule_file);
    puts("complete to generate data capsule file.");


    /**
     * step 5. 생성된 SharedSecret(ssk)를 파일로 저장.
    */
   
    FILE* ssk_file = fopen(ssk_file_path, "wb");
    // puts("generate ssk file..");
    // printf("ssk_file_path = %s\n", ssk_file_path);
    if(ssk_file == NULL) {
        puts("failed to generate ssk file..");
        goto err;
    }

    fwrite(&oSharedSecret[1].type, sizeof(NT_ULONG), 1, ssk_file);
    fwrite(&oSharedSecret[1].ulValueLen, sizeof(NT_ULONG), 1, ssk_file);
    fwrite(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, 1, ssk_file);
    fwrite(&oSharedSecret[1].bSensitive, sizeof(NT_BBOOL), 1, ssk_file);
    fwrite(&oSharedSecret[1].bAlloc, sizeof(NT_BBOOL), 1, ssk_file);
    fclose(ssk_file);
    puts("complete to generate ssk file.");

    // check ssk
    // NS_hex_dump(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, (NT_BYTE_PTR) "shared secret1");

    // printf("capsule type: %d\n", oEncryptedData[1].type);
    // printf("capsule len: %d\n", oEncryptedData[1].ulValueLen);
    // printf("capsule alloc: %d\n", oEncryptedData[1].bAlloc);
    // printf("capsule sensitive: %d\n", oEncryptedData[1].bSensitive);

    // printf("ssk type: %d\n", oSharedSecret[1].type);
    // printf("ssk len: %d\n", oSharedSecret[1].ulValueLen);
    // printf("ssk alloc: %d\n", oSharedSecret[1].bAlloc);
    // printf("ssk sensitive: %d\n", oSharedSecret[1].bSensitive);
    

err:
    NS_clear_object(&oPublicKey, 2);
    NS_clear_object(&oEncryptedData, 2);
    NS_clear_object(&oSharedSecret, 2);

    if(alloc_flag) {
        free(capsule_file_path);
        free(ssk_file_path);
    }
    
    free(attr_type);
    free(attr_ValLen);
    free(attr_pValue);
    free(attr_bSensitive);
    free(attr_bAlloc);

}
