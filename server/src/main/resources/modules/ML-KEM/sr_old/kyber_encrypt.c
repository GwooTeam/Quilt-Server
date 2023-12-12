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
void kyber_encrypt(const char* ssk_path, const char* plain_path, const char* cipher_path) {

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

    NT_OBJECT oData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, TRUE, FALSE}
    };

    NT_OBJECT oEncryptedData = {
        {NAT_OBJECT_TYPE, &data_type, sizeof(data_type), FALSE, FALSE},
        {NAT_VALUE, NULL, 0, FALSE, FALSE}};

    NT_RV ret;

    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL);
    // printf("current status = %d\n", NS_get_state());


    /**
     * Step 1. 경로 설정
     * 암호화한 데이터를 저장할 파일의 경로를 설정.
     */

    char* cipher_file_path;
    int alloc_flag = 0;
    // printf("input cipher_file_path: %s\n", cipher_path);
    if(cipher_path) { // <입력한 경로 + 파일 이름>으로 파일 생성
        size_t cipher_path_len = strlen(cipher_path);
        cipher_file_path = calloc(cipher_path_len+50, 1);
        alloc_flag = 1;

        strncpy(cipher_file_path, cipher_path, cipher_path_len);
        strcat(cipher_file_path, "/kyber_encrypted.bin");
    }
    else {
        cipher_file_path = "kyber_encrypted.bin";
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
     * Step 3. 암호화 대상 데이터 추출
     * 암호화할 데이터를 파일로부터 읽어옴
     */

    FILE* plain_file = fopen(plain_path, "rb");
    if(plain_file == NULL) {
        puts("failed to open plain file..");
        goto err;
    }

    // 파일 크기 계산
    NT_ULONG plain_file_size;
    NT_ULONG padding;

    fseek(plain_file, 0, SEEK_END);
    plain_file_size = ftell(plain_file);
    fseek(plain_file, 0, SEEK_SET);

    padding = 16 - (plain_file_size % 16);
    // printf("plain_file_size: %d\n", plain_file_size);
    // printf("padding: %d\n", padding);

    // 데이터 읽어오기
    NT_VOID_PTR plainData = (NT_VOID_PTR)calloc(plain_file_size + padding, 1);
    fread(plainData, plain_file_size, 1, plain_file);

    char* tmpBuf = (char*)malloc(padding); 
    int i;
    for(i=0; i<padding; i++) {
        tmpBuf[i] = '\0';
    }

    strcat((char*)plainData, tmpBuf);

    // oData에 할당
    oData[1].pValue = plainData;
    oData[1].ulValueLen = plain_file_size + padding;
    
    free(tmpBuf);

    // check oData
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, (NT_BYTE_PTR) "source data");


    /**
     * Step 4. 암호화 초기작업
     */
    if ((ret = NS_encrypt_init(&encctx,
                               (NT_OBJECT_PTR)&oKey)) != NRC_OK)
    {
        printf("NS_encrypt_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }


    /**
     * Step 5. 암호화
     * NS_encrypt 호출 전에 반드시 NS_encrypt_init로 초기 작업을 수행해야 한다.
     */
    if ((ret = NS_encrypt(&encctx,
                          (NT_OBJECT_PTR)&oData,
                          (NT_OBJECT_PTR)&oEncryptedData)) != NRC_OK)
    {
        printf("NS_encrypt failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }
    
    // NS_hex_dump(oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, (NT_BYTE_PTR) "encrypted data");


    /**
     * Step 6. 암호 데이터 파일 저장
     * 암호화한 데이터를 파일로 저장
     */

    FILE* cipher_file;
    // puts("generate cipher file..");
    // printf("cipher_file_path = %s\n", cipher_file_path);
    cipher_file = fopen(cipher_file_path, "wb");
    if(cipher_file == NULL) {
        printf("failed to generate encrypted file.\n");
        goto err;
    }

    fwrite(&oEncryptedData[1].type, sizeof(NT_ULONG), 1, cipher_file);
    fwrite(&oEncryptedData[1].ulValueLen, sizeof(NT_ULONG), 1, cipher_file);
    fwrite(oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, 1, cipher_file);
    fwrite(&oEncryptedData[1].bSensitive, sizeof(NT_BBOOL), 1, cipher_file);
    fwrite(&oEncryptedData[1].bAlloc, sizeof(NT_BBOOL), 1, cipher_file);
    fclose(cipher_file);
    puts("complete to generate encrypted file.");


err:
    NS_clear_object(&oKey, 2);
    NS_clear_object(&oEncryptedData, 2);

    free(attr_type);
    free(attr_ValLen);
    free(attr_pValue);
    free(attr_bSensitive);
    free(attr_bAlloc);

}

