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
void kyber_encapsulate_raw(const char* puk_val) {

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


    /**
     * Step 0. 모드 변경
     * 양자내성암호 모듈을 사용하기 위해 현재 암호모듈의 상태를 다음과 같이 변경한다.
     */
    // printf("current status = %d\n", NS_get_state());
    NS_change_state(NST_MODULE_DISAPPROVAL_PQC);
    // printf("current status = %d\n", NS_get_state());


    /**
     * step 1. 캡슐화에 쓸 공개키 추출
     * 인자로 전달된 공개키를 읽어서 oPublicKey에 저장.
    */

    size_t puk_size = strlen(puk_val) / 2;
    // printf("puk_len: %d\n", puk_len);
    oPublicKey[1].type = NAT_VALUE;

    oPublicKey[1].pValue = (NT_VOID_PTR)calloc(1184, 1);
    hexToByte(puk_val, (unsigned char*)oPublicKey[1].pValue, 1184);

    oPublicKey[1].ulValueLen = puk_size;
    oPublicKey[1].bAlloc = TRUE;
    oPublicKey[1].bSensitive = FALSE;

    // check public key
    // NS_hex_dump(oPublicKey[1].pValue, oPublicKey[1].ulValueLen, (NT_BYTE_PTR) "public key");


    /**
     * Step 2. 캡슐화 초기작업
     */
    if ((ret = NS_encapsulate_init(&kyberctx, (NT_OBJECT_PTR)&oPublicKey)) != NRC_OK)
    {
        fprintf(stderr, "NS_encapsulate_init failed: %s\n", NS_get_errmsg(ret));
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
        fprintf(stderr, "NS_encapsulate failed: %s\n", NS_get_errmsg(ret));
        goto err;
    }

    // NS_hex_dump(oEncryptedData[1].pValue,
    //             oEncryptedData[1].ulValueLen, (NT_BYTE_PTR) "encrypted data");

    
    /**
     * step 4. 캡슐화한 데이터를 표준 출력으로 출력.
    */

    printVal("encapsulated=", (unsigned char*)oEncryptedData[1].pValue, oEncryptedData[1].ulValueLen);

    
    /**
     * step 5. 생성된 SharedSecret(ssk)를 표준 출력으로 출력.
    */

    printVal("ssk=", (unsigned char*)oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen);

    // printVal("puk=", (unsigned char*)oPublicKey[1].pValue, oPublicKey[1].ulValueLen);
    // printf("puk ulValLen: %d\n", oPublicKey[1].ulValueLen);

    // check ssk
    // NS_hex_dump(oSharedSecret[1].pValue, oSharedSecret[1].ulValueLen, (NT_BYTE_PTR) "shared secret1");

err:
    NS_clear_object(&oPublicKey, 2);
    NS_clear_object(&oEncryptedData, 2);
    NS_clear_object(&oSharedSecret, 2);

}
