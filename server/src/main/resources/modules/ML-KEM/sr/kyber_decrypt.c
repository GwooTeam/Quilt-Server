#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

/// @brief Kyber768 Standard

/// - security level: Level 3
/// - matrix computation: No
/// - symmetric primitive: SHA3
/// - randomized signing: No

/* kyber decrypt module */
void kyber_decrypt(const char* ssk_path, const char* cipher_path, const char* plain_path) {

    NT_ULONG enc_type = NOB_CTX_AES_ECB;
    NT_ULONG skey_type = NOB_SHARED_SECRET;
    NT_ULONG data_type = NOB_DATA;

    NT_BYTE iv[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

    NT_CONTEXT encctx = {
        {NAT_OBJECT_TYPE, &enc_type, sizeof(enc_type), FALSE, FALSE},
        {NAT_AES_IV, iv, NMC_AES_BLOCK_BYTE_LEN, TRUE, FALSE},
    };

    NT_OBJECT oKey = {
        {NAT_OBJECT_TYPE, &skey_type, sizeof(skey_type), FALSE, FALSE},
        {NAT_VALUE, NULL, NMC_AES256_KEY_BYTE_LEN, TRUE, FALSE}
    };

    NT_OBJECT oEncryptedData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

    NT_OBJECT oDecryptedData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}};

    NT_RV ret;

    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL_PQC);
    // printf("current status = %d\n", NS_get_state());


    /**
     * Step 1. 경로 설정
     * 복호화한 데이터를 저장할 파일의 경로를 설정.
     */

    char* plain_file_path;
    int alloc_flag = 0;
    if(plain_path) { // <입력한 경로 + 파일 이름>으로 파일 생성
        size_t plain_path_len = strlen(plain_path);
        plain_file_path = calloc(plain_path_len+50, 1);
        alloc_flag = 1;

        strncpy(plain_file_path, plain_path, plain_path_len);
        strcat(plain_file_path, "/kyber_decrypted.bin");
    }
    else {
        plain_file_path = "kyber_decrypted.bin";
    }


    /**
     * Step 2. sharedSecret 추출
     * 암호화에 사용할 ssk(sharedSecret)를 파일로부터 추출.
     */

    NT_ULONG_PTR attr_type = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_ULONG_PTR attr_ValLen = (NT_ULONG_PTR)calloc(sizeof(NT_ULONG), 1);
    NT_BBOOL* attr_bSensitive = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);
    NT_BBOOL* attr_bAlloc = (NT_BBOOL*)calloc(sizeof(NT_BBOOL), 1);

    FILE* ssk_file = fopen(ssk_path, "rb");
    if(ssk_file == NULL) {
        puts("failed to open ssk file..");
        goto err;
    }

    // 데이터 읽기
    fread(attr_type, sizeof(NT_ULONG), 1, ssk_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, ssk_file);
    NT_VOID_PTR attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);

    fread(attr_pValue, *attr_ValLen, 1, ssk_file);
    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, ssk_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, ssk_file);

    // 오브젝트에 데이터 복사
    oKey[1].type = *attr_type;
    oKey[1].ulValueLen = *attr_ValLen;

    oKey[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oKey[1].pValue, attr_pValue, *attr_ValLen);
    
    oKey[1].bSensitive = *attr_bSensitive;
    oKey[1].bAlloc = *attr_bAlloc;

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "shared Secret");


    /**
     * Step 3. 암호 데이터 추출
     * 암호 데이터(복호화 대상)을 파일로부터 읽어옴
     */

    FILE* cipher_file = fopen(cipher_path, "rb");
    if(cipher_file == NULL) {
        puts("failed to open cipher file..");
        goto err;
    }

    // 데이터 담아둘 임시변수 초기화
    // puts("read data from cipher file..");
    memset(attr_type, 0, sizeof(NT_ULONG));
    // memset(attr_pValue, 0, *attr_ValLen);
    memset(attr_ValLen, 0, sizeof(NT_ULONG));
    memset(attr_bSensitive, 0, sizeof(NT_BBOOL));
    memset(attr_bAlloc, 0, sizeof(NT_BBOOL));
    free(attr_pValue);

    // 암호화된 데이터 읽어오기
    fread(attr_type, sizeof(NT_ULONG), 1, cipher_file);
    fread(attr_ValLen, sizeof(NT_ULONG), 1, cipher_file);

    attr_pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    fread(attr_pValue, *attr_ValLen, 1, cipher_file);

    fread(attr_bSensitive, sizeof(NT_BBOOL), 1, cipher_file);
    fread(attr_bAlloc, sizeof(NT_BBOOL), 1, cipher_file);
    fclose(cipher_file);
    printf("success to read capsulated file.\n");

    // oEncryptedData에 할당
    oEncryptedData[1].type = *attr_type;
    oEncryptedData[1].ulValueLen = *attr_ValLen;

    oEncryptedData[1].pValue = (NT_VOID_PTR)calloc(*attr_ValLen, 1);
    memcpy(oEncryptedData[1].pValue, attr_pValue, *attr_ValLen);

    oEncryptedData[1].bSensitive = *attr_bSensitive;
    oEncryptedData[1].bAlloc = *attr_bAlloc;

    // check oEncryptedData
    // NS_hex_dump(oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, (NT_BYTE_PTR) "encrypted data");


    /**
     * Step 4. 복호화 초기작업
     */
    if ((ret = NS_decrypt_init(&encctx,
                               (NT_OBJECT_PTR)&oKey)) != NRC_OK)
    {
        printf("NS_decrypt_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }


    /**
     * Step 5. 복호화
     * NS_decrypt() 호출 전에 반드시 NS_decrypt_init()로 초기 작업을 수행해야 한다.
     */
    if ((ret = NS_decrypt(&encctx,
                          (NT_OBJECT_PTR)&oEncryptedData,
                          (NT_OBJECT_PTR)&oDecryptedData)) != NRC_OK)
    {
        printf("NS_decrypt failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen, (NT_BYTE_PTR) "decrypted data");

    /**
     * Step 6. 복호 데이터 파일 저장
     * 복호화한 데이터를 파일로 저장
     */

    FILE* plain_file;
    // puts("generate plain file..");
    // printf("plain_file_path = %s\n", plain_file_path);
    plain_file = fopen(plain_file_path, "wb");
    if(plain_file == NULL) {
        printf("failed to generate cipher file.\n");
        goto err;
    }

    // fwrite(&oDecryptedData[1].type, sizeof(NT_ULONG), 1, plain_file);
    // fwrite(&oDecryptedData[1].ulValueLen, sizeof(NT_ULONG), 1, plain_file);
    fwrite(oDecryptedData[1].pValue, oDecryptedData[1].ulValueLen, 1, plain_file);
    // fwrite(&oDecryptedData[1].bSensitive, sizeof(NT_BBOOL), 1, plain_file);
    // fwrite(&oDecryptedData[1].bAlloc, sizeof(NT_BBOOL), 1, plain_file);
    fclose(plain_file);
    puts("complete to generate decrypted file.");


err:
    NS_clear_object(&oKey, 2);
    NS_clear_object(&oEncryptedData, 2);
    NS_clear_object(&oDecryptedData, 2);

    free(attr_type);
    free(attr_ValLen);
    free(attr_pValue);
    free(attr_bSensitive);
    free(attr_bAlloc);

}

