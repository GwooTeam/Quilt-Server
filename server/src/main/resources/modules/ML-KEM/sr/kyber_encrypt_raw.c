#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "nsc_api.h"

#include "quilt_api.h"

/// @brief Kyber768 Standard

/// - security level: Level 3
/// - matrix computation: No
/// - symmetric primitive: SHA3
/// - randomized signing: No

/* kyber encrypt module */
void kyber_encrypt_raw(const char* ssk_val, const char* plain_val) {

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
     * Step 1. sharedSecret 추출
     * 인자로 전달된 ssk를 oKey에 저장.
     */

    size_t ssk_size = strlen(ssk_val) / 2; // 32
    

    oKey[1].pValue = (NT_VOID_PTR)calloc(ssk_size, 1); // allocate 32byte
    hexToByte(ssk_val, (unsigned char*)oKey[1].pValue, ssk_size);
    
    oKey[1].type = NAT_VALUE;
    oKey[1].ulValueLen = ssk_size;
    oKey[1].bAlloc = TRUE;
    oKey[1].bSensitive = TRUE;
    

    // check ssk
    // NS_hex_dump(oKey[1].pValue, oKey[1].ulValueLen, (NT_BYTE_PTR) "shared Secret");


    /**
     * Step 2. 암호화 대상 데이터 추출
     * 인자로 전달된 데이터를 oData에 저장.
     */

    size_t plain_val_len = strlen(plain_val);
    // printf("plain_val_len: %d\n", plain_val_len);
    unsigned int padding = 16 - (plain_val_len % 16);

    unsigned char* plain_val_pad = (unsigned char*)malloc(plain_val_len + padding);
    strncpy(plain_val_pad, plain_val, plain_val_len);

    unsigned char* tmpBuf = (char*)malloc(padding);
    int i;
    for(i=0; i<padding-1; i++) {
        tmpBuf[i] = '\0';
    }
    tmpBuf[plain_val_len + padding -1] = '\0';

    strcat(plain_val_pad, tmpBuf);

    oData[1].type = NAT_VALUE;
    oData[1].pValue = (NT_VOID_PTR)plain_val_pad;
    oData[1].ulValueLen = plain_val_len + padding;
    oData[1].bAlloc = TRUE;
    oData[1].bSensitive = FALSE;

    free(tmpBuf);

    
    // check oData
    // NS_hex_dump(oData[1].pValue, oData[1].ulValueLen, (NT_BYTE_PTR) "source data");


    /**
     * Step 3. 암호화 초기작업
     */
    if ((ret = NS_encrypt_init(&encctx,
                               (NT_OBJECT_PTR)&oKey)) != NRC_OK)
    {
        fprintf(stderr, "NS_encrypt_init failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }


    /**
     * Step 4. 암호화
     * NS_encrypt 호출 전에 반드시 NS_encrypt_init로 초기 작업을 수행해야 한다.
     */
    if ((ret = NS_encrypt(&encctx,
                          (NT_OBJECT_PTR)&oData,
                          (NT_OBJECT_PTR)&oEncryptedData)) != NRC_OK)
    {
        fprintf(stderr, "NS_encrypt failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }
    
    // NS_hex_dump(oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen, (NT_BYTE_PTR) "encrypted data");


    /**
     * Step 5. 암호 데이터 출력
     * 암호화한 데이터를 표준 출력으로 출력.
     */

    printVal("enc=", (unsigned char*)oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen);
    fprintf(stdout, "length=%ld", plain_val_len);
    

err:
    NS_clear_object(&oKey, 2);
    NS_clear_object(&oEncryptedData, 2);

}

