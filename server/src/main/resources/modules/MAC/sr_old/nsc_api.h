#ifndef _NSCRYPTO_
#define _NSCRYPTO_

#ifdef __cplusplus
extern "C"
{
#endif

#ifndef NT_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif
#endif /* !NT_DISABLE_TRUE_FALSE */

#define NMC_TRUE TRUE
#define NMC_FALSE FALSE

	typedef unsigned char NT_BYTE;
	typedef NT_BYTE NT_CHAR;
	typedef NT_BYTE NT_BBOOL;

	typedef unsigned int NT_ULONG;
	typedef int NT_LONG;

	typedef NT_BYTE *NT_BYTE_PTR;
	typedef NT_CHAR *NT_CHAR_PTR;
	typedef NT_ULONG *NT_ULONG_PTR;
	typedef void *NT_VOID_PTR;

	/* NSCrypto library의 버전 정보 */
	typedef struct _NT_VERSION
	{
		NT_BYTE major; /* integer portion of version number  */
		NT_BYTE minor; /* 1/100ths portion of version number */
	} NT_VERSION, *NT_VERSION_PTR;

	/* NSCrypto library의 세부 정보 */
	typedef struct _NT_INFO
	{
		NT_VERSION nsapiVersion;		/* interface version  */
		NT_CHAR manufacturerID[32];		/* blank padded       */
		NT_ULONG flags;					/* must be zero       */
		NT_CHAR libraryDescription[32]; /* blank padded       */
		NT_VERSION libraryVersion;		/* version of library */
	} NT_INFO, *NT_INFO_PTR;

	typedef struct _NT_ATTRIBUTE
	{
		NT_ULONG type;		 /* 데이터의 타입				*/
		NT_VOID_PTR pValue;	 /* 데이터						*/
		NT_ULONG ulValueLen; /* 데이터의 byte 단위 크기		*/
		NT_BBOOL bSensitive; /* 보안상 민감한 데이터 여부	*/
		NT_BBOOL bAlloc;	 /* pValue에 대한 라이브러리
								내부에서의 메모리 할당 여부	*/
	} NT_ATTRIBUTE, *NT_ATTRIBUTE_PTR;

#define NMC_SZ_OBJECT 8
	typedef NT_ATTRIBUTE NT_OBJECT[NMC_SZ_OBJECT];
	typedef NT_OBJECT *NT_OBJECT_PTR;

#define NMC_SZ_CONTEXT_INTERNAL 10
#define NMC_SZ_CONTEXT_EXTERNAL 10
#define NMC_SZ_CONTEXT NMC_SZ_CONTEXT_INTERNAL + NMC_SZ_CONTEXT_EXTERNAL

	typedef NT_ATTRIBUTE NT_CONTEXT[NMC_SZ_CONTEXT];
	typedef NT_CONTEXT *NT_CONTEXT_PTR;

	/***********************************************************************
		함수의 반환코드를 나타내는 자료형
	***********************************************************************/
	typedef NT_ULONG NT_RV;

/***********************************************************************
	Return value
***********************************************************************/
/* return value : 성공시 */
#define NRC_OK 0

/* return value : 실패시 */
#define NRC_DEFAULT_ERROR -1

/***********************************************************************
	Global constants
***********************************************************************/
#ifdef WIN32
#ifdef SHLIB_EXPORTS
#define NSGLOBAL __declspec(dllexport)
#else
#define NSGLOBAL __declspec(dllimport)
#endif
#endif

/***********************************************************************
	Constants
***********************************************************************/
/* ECDSA 서명 크기 */
#define NMC_ECDSA_SIGN_BYTE_LEN 1024

/* ECDH Key 크기 */
#define NMC_ECDH_KEY_BYTE_LEN 21

/* SEED block 크기 */
#define NMC_SEED_BLOCK_BYTE_LEN 16
#define NMC_SEED_KEY_BYTE_LEN 16

/* AES block 크기 */
#define NMC_AES_BLOCK_BYTE_LEN 16
#define NMC_AES128_KEY_BYTE_LEN 16
#define NMC_AES192_KEY_BYTE_LEN 24
#define NMC_AES256_KEY_BYTE_LEN 32

/* ARIA block 크기 */
#define NMC_ARIA_BLOCK_BYTE_LEN 16
#define NMC_ARIA128_KEY_BYTE_LEN 16
#define NMC_ARIA192_KEY_BYTE_LEN 24
#define NMC_ARIA256_KEY_BYTE_LEN 32

/* LEA block 크기 */
#define NMC_LEA_BLOCK_BYTE_LEN 16
#define NMC_LEA128_KEY_BYTE_LEN 16
#define NMC_LEA192_KEY_BYTE_LEN 24
#define NMC_LEA256_KEY_BYTE_LEN 32

/* PIPO block 크기 */
#define NMC_PIPO_BLOCK_BYTE_LEN 8
#define NMC_PIPO128_KEY_BYTE_LEN 16
#define NMC_PIPO256_KEY_BYTE_LEN 32

/* SHA224 해쉬 크기 */
#define NMC_SHA224_HASH_BYTE_LEN 28

/* SHA256 해쉬 크기 */
#define NMC_SHA256_HASH_BYTE_LEN 32

/* SHA384 해쉬 크기 */
#define NMC_SHA384_HASH_BYTE_LEN 48

/* SHA512 해쉬 크기 */
#define NMC_SHA512_HASH_BYTE_LEN 64

/* SHA3-224 해쉬 크기 */
#define NMC_SHA3_224_HASH_BYTE_LEN 28

/* SHA3-256 해쉬 크기 */
#define NMC_SHA3_256_HASH_BYTE_LEN 32

/* SHA3-384 해쉬 크기 */
#define NMC_SHA3_384_HASH_BYTE_LEN 48

/* SHA3-512 해쉬 크기 */
#define NMC_SHA3_512_HASH_BYTE_LEN 64

/* 최대 해쉬 크기 */
#define NMC_MAX_HASH_BYTE_LEN 64

/* Dilithium 공개키/개인키/서명 최대 크기 */
#define NMC_MAX_DILITHIUM_PUBKEY_SIZE 2592
#define NMC_MAX_DILITHIUM_PRIKEY_SIZE 4864
#define NMC_MAX_DILITHIUM_SIG_SIZE 4595

/* Shared Secret 크기 */
#define NMC_SHARED_SECRET_BYTE_LEN 32

	/* ??? Label ?????*/
#define NMC_MAX_LABEL_BYTE_LEN 256

	/***********************************************************************
		NT_CONTEXT의 type들은 NT_CONTEXT의 첫번째 NT_ATTRIBUTE에 다음과 같이
		지정될 수 있다.
	***********************************************************************/
	enum NSCE_CONTEXT_TYPE
	{
		/*SEED */
		NOB_CTX_SEED_KEY_GEN,
		NOB_CTX_SEED_ECB,
		NOB_CTX_SEED_CBC,
		NOB_CTX_SEED_CBC_PAD,
		NOB_CTX_SEED_OFB,
		NOB_CTX_SEED_CFB,
		NOB_CTX_SEED_CMAC,

		/*ARIA*/
		NOB_CTX_ARIA_KEY_GEN,
		NOB_CTX_ARIA_ECB,
		NOB_CTX_ARIA_CBC,
		NOB_CTX_ARIA_CBC_PAD,
		NOB_CTX_ARIA_OFB,
		NOB_CTX_ARIA_CFB,
		NOB_CTX_ARIA_CMAC,

		/*AES*/
		NOB_CTX_AES_KEY_GEN,
		NOB_CTX_AES_ECB,
		NOB_CTX_AES_CBC,
		NOB_CTX_AES_CBC_PAD,
		NOB_CTX_AES_OFB,
		NOB_CTX_AES_CFB,
		NOB_CTX_AES_CMAC,

		/*SHA224*/
		NOB_CTX_SHA224,
		NOB_CTX_SHA224_HMAC,

		/*SHA256*/
		NOB_CTX_SHA256,
		NOB_CTX_SHA256_HMAC,

		/*SHA384*/
		NOB_CTX_SHA384,
		NOB_CTX_SHA384_HMAC,

		/*SHA512*/
		NOB_CTX_SHA512,
		NOB_CTX_SHA512_HMAC,

		/*RSA*/
		NOB_CTX_RSA_KEYPAIR_GEN,
		NOB_CTX_RSA_PKCK_V15_ENCRYPT,
		NOB_CTX_RSA_OAEP_ENCRYPT_SHA256,
		NOB_CTX_RSA_OAEP_ENCRYPT_SHA384,
		NOB_CTX_RSA_OAEP_ENCRYPT_SHA512,
		NOB_CTX_RSASSA_PKCK_SHA256,
		NOB_CTX_RSASSA_PKCK_SHA384,
		NOB_CTX_RSASSA_PKCK_SHA512,
		NOB_CTX_RSASSA_PSS_SHA256,
		NOB_CTX_RSASSA_PSS_SHA384,
		NOB_CTX_RSASSA_PSS_SHA512,
		NOB_CTX_RSA_ENCRYPT,

		/*ECC*/
		NOB_CTX_EC_KEYPAIR_GEN,
		NOB_CTX_ECDH_DERIVE,

		/*RAND KEY*/
		NOB_CTX_SYM_KEY_GEN,

		/*ECC*/
		NOB_CTX_ECDSA_SHA256,
		NOB_CTX_ECDSA_SHA384,
		NOB_CTX_ECDSA_SHA512,

		/* Hash DRBG */
		NOB_HASH_DRBG_SHA256,
		NOB_HASH_DRBG_SHA384,
		NOB_HASH_DRBG_SHA512,

		/* GCM */
		NOB_CTX_ARIA_GCM,
		NOB_CTX_SEED_GCM,
		NOB_CTX_LEA_GCM,
		NOB_CTX_AES_GCM,

		/*LEA*/
		NOB_CTX_LEA_KEY_GEN,
		NOB_CTX_LEA_ECB,
		NOB_CTX_LEA_CBC,
		NOB_CTX_LEA_CBC_PAD,
		NOB_CTX_LEA_OFB,
		NOB_CTX_LEA_CFB,
		NOB_CTX_LEA_CMAC,

		/* CTR */
		NOB_CTX_SEED_CTR,
		NOB_CTX_ARIA_CTR,
		NOB_CTX_LEA_CTR,
		NOB_CTX_AES_CTR,

		/* GMAC */
		NOB_CTX_ARIA_GMAC,
		NOB_CTX_SEED_GMAC,
		NOB_CTX_LEA_GMAC,
		NOB_CTX_AES_GMAC,

		/* PIPO */
		NOB_CTX_PIPO_KEY_GEN,
		NOB_CTX_PIPO_ECB,
		NOB_CTX_PIPO_CBC,
		NOB_CTX_PIPO_CBC_PAD,
		NOB_CTX_PIPO_OFB,
		NOB_CTX_PIPO_CFB,
		NOB_CTX_PIPO_CTR,

		/* PBKDF */
		NOB_PBKDF2_HMAC_SHA224,
		NOB_PBKDF2_HMAC_SHA256,
		NOB_PBKDF2_HMAC_SHA384,
		NOB_PBKDF2_HMAC_SHA512,

		/* SHA3-224*/
		NOB_CTX_SHA3_224,
		NOB_CTX_SHA3_224_HMAC,

		/* SHA3-256*/
		NOB_CTX_SHA3_256,
		NOB_CTX_SHA3_256_HMAC,

		/* SHA3-384*/
		NOB_CTX_SHA3_384,
		NOB_CTX_SHA3_384_HMAC,

		/* SHA3-512*/
		NOB_CTX_SHA3_512,
		NOB_CTX_SHA3_512_HMAC,

		/* SHAKE*/
		NOB_CTX_SHAKE128,
		NOB_CTX_SHAKE256,

		/* Dilithium */
		NOB_CTX_DILITHIUM_KEYPAIR_GEN,
		NOB_CTX_DILITHIUM,

		/* Kyber */
		NOB_CTX_KYBER_PKE_KEYPAIR_GEN,
		NOB_CTX_KYBER_PKE,
		NOB_CTX_KYBER_KEM_KEYPAIR_GEN,
		NOB_CTX_KYBER_KEM,

		/* Falcon */
		NOB_CTX_FALCON_KEYPAIR_GEN,
		NOB_CTX_FALCON,

		/*
		새로운 알고리즘을 이 곳에 추가한다.
		...
		*/

		/*
		NOB_CTX_NONE을 알고리즘 추가시
		가장 마지막에 위치하도록 정리
		*/

		NOB_CTX_NONE,

	};

	/***********************************************************************
		공개키, 개인키, 비밀키, 데이터, 비밀공유키 등을 나타내는 NT_OBJECT의 type들은
		NT_OBJECT의 첫번째 NT_ATTRIBUTE에 다음과 같이 지정될 수 있다.
	***********************************************************************/
	enum NSCE_OBJECT_TYPE
	{
		NOB_PUBLIC_KEY = 0,
		NOB_PRIVATE_KEY,
		NOB_SECRET_KEY,
		NOB_DATA,
		NOB_SHARED_SECRET,
	};

	/***********************************************************************
	NT_ATTRIBUTE types
	***********************************************************************/
	enum NSCE_ATTRIBUTE_TYPE
	{
		/* 값을 나타내는 NT_ATTRIBUTE                             */
		NAT_VALUE = 0,
		/* 타원곡선 번호를 나타내는 NT_ATTRIBUTE                  */
		NAT_EC_NUMBER,
		/* ECC공개키의 형태를 나타내는 NT_ATTRIBUTE               */
		NAT_ECPT_FORM,
		/* ECDH 키 합의시 상대방의 공개키를 나타내는 NT_ATTRIBUTE */
		NAT_ECDH_PEERS_PUBLICKEY,
		/* 난수 생성기의 종류를 나태내는 NT_ATTRIBUTE             */
		NAT_RANDOM_FUNCTION_TYPE,
		/* RSA의 prime type...*/
		NAT_RSA_PRIME_TYPE,
		/* RSA의 bits...*/
		NAT_RSA_BITS,
		/* SEED 블록 암호의 초기 벡터를 나타내는 NT_ATTRIBUTE     */
		NAT_SEED_IV,
		/* AES 블록 암호의 초기 벡터를 나타내는 NT_ATTRIBUTE     */
		NAT_AES_IV,
		/* ARIA 블록 암호의 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_ARIA_IV,
		/*	각종 파라미터의(공개키 주체,OAEP label 등..) label을
		나타내는 NT_ATTRIBUTE*/
		NAT_LABEL,
		/* NSCE_OBJECT_TYPE (or NSCE_CONTEXT_TYPE) type을 나타내는 NT_ATTRIBUTE*/
		NAT_OBJECT_TYPE,
		/* 사용자 요구 RSA Public Exponent를 나타내는 NT_ATTRIBUTE */
		NAT_REQ_RSA_PUBLIC_EXPONENT,
		/* ARIA 블록 암호의 GCM용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_ARIA_GCM_IV,
		/* ARIA 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_ARIA_GCM_AAD,
		/* ARIA 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_ARIA_GCM_MAC,
		/* SEED 블록 암호의 GCM용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_SEED_GCM_IV,
		/* SEED 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_SEED_GCM_AAD,
		/* SEED 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_SEED_GCM_MAC,
		/* AES 블록 암호의 GCM용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_AES_GCM_IV,
		/* AES 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_AES_GCM_AAD,
		/* AES 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_AES_GCM_MAC,
		/* LEA 블록 암호의 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_LEA_IV,
		/* LEA 블록 암호의 GCM용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_LEA_GCM_IV,
		/* LEA 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_LEA_GCM_AAD,
		/* LEA 블록 암호의 GCM용 추가 인증 데이터를 나타내는 NT_ATTRIBUTE    */
		NAT_LEA_GCM_MAC,
		/* ARIA 블록 암호의 GMAC용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_ARIA_GMAC_IV,
		/* SEED 블록 암호의 GMAC용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_SEED_GMAC_IV,
		/* AES 블록 암호의 GMAC용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_AES_GMAC_IV,
		/* LEA 블록 암호의 GMAC용 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_LEA_GMAC_IV,
		/* DRBG의 예측내성 옵션을 나타내는 NT_ATTRIBUTE    */
		NAT_DRBG_PRE_RES_FLAG,
		/* DRBG의 추가 입력을 나타내는 NT_ATTRIBUTE    */
		NAT_DRBG_ADD_INPUT,
		/* PIPO 블록 암호의 초기 벡터를 나타내는 NT_ATTRIBUTE    */
		NAT_PIPO_IV,
		/* PBKDF의 솔트를 나타내는 NT_ATTRIBUTE    */
		NAT_PBKDF_SALT,
		/* Dilithium의 symmetric primitive 옵션을 나타내는 NT_ATTRIBUTE */
		NAT_DILITHIUM_SYMMETRIC_PRIMITIVE_TYPE,
		/* Dilithium의 NIST security level을 나타내는 NT_ATTRIBUTE */
		NAT_DILITHIUM_SECURITY_LEVEL,
		/* Dilithium의 공개행렬 생성 옵션을 나타내는 NT_ATTRIBUTE */
		NAT_DILITHIUM_IS_MATRIX_PRECOMPUTED,
		/* Dilithium의 서명 생성 옵션을 나타내는 NT_ATTRIBUTE */
		NAT_DILITHIUM_IS_RANDOMIZING_SIGNING,
		/* Kyber의 symmetric primitive 옵션을 나타내는 NT_ATTRIBUTE */
		NAT_KYBER_SYMMETRIC_PRIMITIVE_TYPE,
		/* Kyber의 NIST security level을 나타내는 NT_ATTRIBUTE */
		NAT_KYBER_SECURITY_LEVEL,
		/* Kyber의 공개행렬 생성 옵션을 나타내는 NT_ATTRIBUTE */
		NAT_KYBER_IS_MATRIX_PRECOMPUTED,
	};

	/* 난수 생성기 종류 */
	enum NSCE_RANDOM_FUNCTION_TYPE
	{
		NOP_RANDOM_FUNCTION_TYPE_HASH_DRBG_SHA256,
		NOP_RANDOM_FUNCTION_TYPE_HASH_DRBG_SHA384,
		NOP_RANDOM_FUNCTION_TYPE_HASH_DRBG_SHA512
	};

	/* named elliptic curve 종류 */
	enum NSCE_FIPS_ECNUM
	{
		NOP_FIPS_K233,
		NOP_FIPS_K283,
		NOP_FIPS_B233,
		NOP_FIPS_B283,
		NOP_FIPS_P224,
		NOP_FIPS_P256,
	};

	/* 타원곡선 점 포맷 */
	enum NSCE_ECPT_FORM
	{
		NOP_ECPT_UNCOMPRESS,
		NOP_ECPT_COMPRESS,
		NOP_ECPT_HYBRID
	};

	enum NSCE_RSA_PRIME_TYPE
	{
		NOP_RSA_PRIMETYPE_PQ,
	};

	/* PQC symmetric primitive option */
	enum NSCE_SYMMETRIC_PRIMITIVE_TYPE
	{
		NOP_SYMMETRIC_PRIMITIVE_STANDARD,
		NOP_SYMMETRIC_PRIMITIVE_AES256CTR,
	};

	/* DILITHIUM security level */
	enum NSCE_DILITHIUM_SECURITY_LEVEL
	{
		NOP_DILITHIUM_LEVEL2 = 2,
		NOP_DILITHIUM_LEVEL3 = 3,
		NOP_DILITHIUM_LEVEL5 = 5,
	};

	/* DILITHIUM matrix precomputation option*/
	enum NSCE_DILITHIUM_IS_MATRIX_PRECOMPUTED
	{
		NOP_DILITHIUM_NO_MAT_PRECOMPUTED,
		NOP_DILITHIUM_MAT_PRECOMPUTED,
	};

	/* DILITHIUM Signing option*/
	enum NSCE_DILITHIUM_IS_RANDOMIZING_SIGNING
	{
		NOP_DILITHIUM_NO_RANDOMIZING_SIGNING,
		NOP_DILITHIUM_RANDOMIZING_SIGNING,
	};

	/* KYBER secrutiy level */
	enum NSCE_KYBER_SECURITY_LEVEL
	{
		NOP_KYBER_512,
		NOP_KYBER_768,
		NOP_KYBER_1024,
	};

	/* KYBER matrix precomputation option*/
	enum NSCE_KYBER_IS_MAT_PRECOMPUTED
	{
		NOP_KYBER_NO_MAT_PRECOMPUTED,
		NOP_KYBER_MAT_PRECOMPUTED,
	};

	/***********************************************************************
		CMVP States
	***********************************************************************/
	enum NSCE_CMVP_STATE
	{
		/*호출성공상태*/
		NST_MODULE_LOADED = 1,
		/*비검증대상 보호함수 모드*/
		NST_MODULE_DISAPPROVAL,
		/*검증대상 보호함수 모드*/
		NST_MODULE_APPROVAL,
		/*오류상태*/
		NST_MODULE_FATAL_ERROR,
		/*종료상태*/
		NST_MODULE_TERMINATE,
		/*동작전 자가시험 상태*/
		NST_MODULE_PUST,
		/*Post-Quantum 모드*/
		NST_MODULE_DISAPPROVAL_PQC,
	};

	/***********************************************************************
	Error Codes
	***********************************************************************/

	/*----------------------------------------------------------------------
	일반 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_COMMON_ERROR
	{
		NRC_ARGUMENTS_BAD = 1000,	/* ??��? ???? : ????? NT_OBJECT??
									??????? NULL?? ???          */
		NRC_CTX_NOT_SUPPORTED,		/* ???????? ??? ??? ????       */
		NRC_INPUT_DATA_EMPTY,		/* ??? NT_OBJECT?? ??? ?????
									NT_ATTRIBUTE?? ?????? ?????
									?????? ???? ???            */
		NRC_INPUT_DATA_TOO_LONG,	/* ??? NT_OBJECT?? ??? ?????
									NT_ATTRIBUTE?? ?????? ?????
									??? ??????? ?? ???          */
		NRC_KEY_TYPE_NOT_SUPPORTED, /* ???????? ??? ? ???         */
		NRC_RADNOM_LENGTH_INVAILD,	/* ???? ?????? ????? ??????
									????							 */
		NRC_SIGN_KEY_EMPTY,
		NRC_FILE_IO_ERROR,				  /* ???? ????? ???? */
		NRC_OBJECT_TYPE_ATTRIBUTE_MISSED, /*Object type ??? ????*/
		NRC_TO_BE_ALLOCATED_PTR_NOT_NULL, /*??? ?????? ??????? NULL?? ???? ???? ????*/

		/*CMVP*/
		NRC_MODULE_PUST_SEED_ECB_ENCTYPT_FAILED, /* 자가시험 SEED ECB 암호화 실패		- 1010 */
		NRC_MODULE_PUST_SEED_CBC_ENCTYPT_FAILED, /* 자가시험 SEED CBC 암호화 실패		*/
		NRC_MODULE_PUST_SEED_OFB_ENCTYPT_FAILED, /* 자가시험 SEED OFB 암호화 실패    */
		NRC_MODULE_PUST_SEED_CFB_ENCTYPT_FAILED, /* 자가시험 SEED CFB 암호화 실패    */
		NRC_MODULE_PUST_SEED_CTR_ENCTYPT_FAILED, /* 자가시험 SEED CTR 암호화 실패    */
		NRC_MODULE_PUST_SEED_GCM_ENCTYPT_FAILED, /* 자가시험 SEED GCM 암호화 실패 	*/
		NRC_MODULE_PUST_SEED_ECB_DECTYPT_FAILED, /* 자가시험 SEED ECB 복호화 실패		*/
		NRC_MODULE_PUST_SEED_CBC_DECTYPT_FAILED, /* 자가시험 SEED CBC 복호화 실패		*/
		NRC_MODULE_PUST_SEED_OFB_DECTYPT_FAILED, /* 자가시험 SEED OFB 복호화 실패		*/
		NRC_MODULE_PUST_SEED_CFB_DECTYPT_FAILED, /* 자가시험 SEED CFB 복호화 실패		*/
		NRC_MODULE_PUST_SEED_CTR_DECTYPT_FAILED, /* 자가시험 SEED CTR 복호화 실패		- 1020	*/
		NRC_MODULE_PUST_SEED_GCM_DECTYPT_FAILED, /* 자가시험 SEED GCM 복호화 실패		*/
		NRC_MODULE_PUST_ARIA_ECB_ENCTYPT_FAILED, /* 자가시험 ARIA ECB 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_CBC_ENCTYPT_FAILED, /* 자가시험 ARIA CBC 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_OFB_ENCTYPT_FAILED, /* 자가시험 ARIA OFB 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_CFB_ENCTYPT_FAILED, /* 자가시험 ARIA CFB 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_CTR_ENCTYPT_FAILED, /* 자가시험 ARIA CTR 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_GCM_ENCTYPT_FAILED, /* 자가시험 ARIA GCM 암호화 실패		*/
		NRC_MODULE_PUST_ARIA_ECB_DECTYPT_FAILED, /* 자가시험 ARIA ECB 복호화 실패		*/
		NRC_MODULE_PUST_ARIA_CBC_DECTYPT_FAILED, /* 자가시험 ARIA CBC 복호화 실패		*/
		NRC_MODULE_PUST_ARIA_OFB_DECTYPT_FAILED, /* 자가시험 ARIA OFB 복호화 실패		- 1030	*/
		NRC_MODULE_PUST_ARIA_CFB_DECTYPT_FAILED, /* 자가시험 ARIA CFB 복호화 실패		*/
		NRC_MODULE_PUST_ARIA_CTR_DECTYPT_FAILED, /* 자가시험 ARIA CTR 복호화 실패		*/
		NRC_MODULE_PUST_ARIA_GCM_DECTYPT_FAILED, /* 자가시험 ARIA GCM 복호화 실패		*/
		NRC_MODULE_PUST_LEA_ECB_ENCTYPT_FAILED,	 /* 자가시험 LEA ECB 암호화 실패			*/
		NRC_MODULE_PUST_LEA_CBC_ENCTYPT_FAILED,	 /* 자가시험 LEA CBC 암호화 실패  		*/
		NRC_MODULE_PUST_LEA_OFB_ENCTYPT_FAILED,	 /* 자가시험 LEA OFB 암호화 실패			*/
		NRC_MODULE_PUST_LEA_CFB_ENCTYPT_FAILED,	 /* 자가시험 LEA CFB 암호화 실패			*/
		NRC_MODULE_PUST_LEA_CTR_ENCTYPT_FAILED,	 /* 자가시험 LEA CTR 암호화 실패			*/
		NRC_MODULE_PUST_LEA_GCM_ENCTYPT_FAILED,	 /* 자가시험 LEA GCM 암호화 실패			*/
		NRC_MODULE_PUST_LEA_ECB_DECTYPT_FAILED,	 /* 자가시험 LEA ECB 복호화 실패			- 1040	*/
		NRC_MODULE_PUST_LEA_CBC_DECTYPT_FAILED,	 /* 자가시험 LEA CBC 복호화 실패			*/
		NRC_MODULE_PUST_LEA_OFB_DECTYPT_FAILED,	 /* 자가시험 LEA OFB 복호화 실패			*/
		NRC_MODULE_PUST_LEA_CFB_DECTYPT_FAILED,	 /* 자가시험 LEA CFB 복호화 실패			*/
		NRC_MODULE_PUST_LEA_CTR_DECTYPT_FAILED,	 /* 자가시험 LEA CTR 복호화 실패			*/
		NRC_MODULE_PUST_LEA_GCM_DECTYPT_FAILED,	 /* 자가시험 LEA GCM 복호화 실패 		*/

		NRC_MODULE_PUST_HASH_SHA256_FAILED, /* 자가시험 SHA256-HASH 검증 실패			*/
		NRC_MODULE_PUST_HASH_SHA384_FAILED, /* 자가시험 SHA384-HASH 검증 실패			*/
		NRC_MODULE_PUST_HASH_SHA512_FAILED, /* 자가시험 SHA512-HASH 검증 실패			*/

		NRC_MODULE_PUST_RSA_OAEP_2048_ENCRYPT_FAILED, /* 자가시험 RSA 2048 암호화 실패	*/
		NRC_MODULE_PUST_RSA_OAEP_2048_DECRYPT_FAILED, /* 자가시험 RSA 2048 복호화 실패		- 1050 */
		NRC_MODULE_PUST_RSA_OAEP_3072_ENCRYPT_FAILED, /* 자가시험 RSA 3072 암호화 실패*/
		NRC_MODULE_PUST_RSA_OAEP_3072_DECRYPT_FAILED, /* 자가시험 RSA 3072 복호화 실패    */

		NRC_MODULE_PUST_RSASSA_PSS_2048_SIGN_FAILED,   /* 자가시험 RSA PSS 2048 서명 실패   */
		NRC_MODULE_PUST_RSASSA_PSS_2048_VERIFY_FAILED, /* 자가시험 RSA PSS 2048 검증 실패   */
		NRC_MODULE_PUST_RSASSA_PSS_3072_SIGN_FAILED,   /* 자가시험 RSA PSS 3072 서명 실패   */
		NRC_MODULE_PUST_RSASSA_PSS_3072_VERIFY_FAILED, /* 자가시험 RSA PSS 3072 검증 실패   */

		NRC_MODULE_PUST_SHA256_HMAC_SIGN_FAILED,   /* 자가시험 SHA256-HMAC 서명 실패    */
		NRC_MODULE_PUST_SHA256_HMAC_VERIFY_FAILED, /* 자가시험 SHA256-HMAC 검증 실패	 */
		NRC_MODULE_PUST_SHA384_HMAC_SIGN_FAILED,   /* 자가시험 SHA384-HMAC 서명 실패	 */
		NRC_MODULE_PUST_SHA384_HMAC_VERIFY_FAILED, /* 자가시험 SHA384-HMAC 검증 실패	- 1060 */
		NRC_MODULE_PUST_SHA512_HMAC_SIGN_FAILED,   /* 자가시험 SHA512-HMAC 서명 실패	     */
		NRC_MODULE_PUST_SHA512_HMAC_VERIFY_FAILED, /* 자가시험 SHA512-HMAC 검증 실패          */

		NRC_MODULE_PUST_SEED_CMAC_SIGN_FAILED,	 /* 자가시험 SEED-CMAC 서명 실패            */
		NRC_MODULE_PUST_SEED_CMAC_VERIFY_FAILED, /* 자가시험 SEED-CMAC 검증 실패            */
		NRC_MODULE_PUST_ARIA_CMAC_SIGN_FAILED,	 /* 자가시험 ARIA-CMAC 서명 실패            */
		NRC_MODULE_PUST_ARIA_CMAC_VERIFY_FAILED, /* 자가시험 ARIA-CMAC 검증 실패            */
		NRC_MODULE_PUST_LEA_CMAC_SIGN_FAILED,	 /* 자가시험 LEA-CMAC 서명 실패             */
		NRC_MODULE_PUST_LEA_CMAC_VERIFY_FAILED,	 /* 자가시험 LEA-CMAC 검증 실패     */

		NRC_MODULE_PUST_HASH_DRBG_SHA256_FAILED, /* 자가시험 HASH DRBG SHA256 초기화 실패  			*/
		NRC_MODULE_PUST_HASH_DRBG_SHA384_FAILED, /* 자가시험 HASH DRBG SHA384 초기화 실패		- 1070	*/
		NRC_MODULE_PUST_HASH_DRBG_SHA512_FAILED, /* 자가시험 HASH DRBG SHA512 초기화 실패		*/

		NRC_MODULE_PUST_ECDSA_K233_SIGN_FAILED,	  /* 자가시험 ECDSA k233 서명 실패             */
		NRC_MODULE_PUST_ECDSA_K233_VERIFY_FAILED, /* 자가시험 ECDSA k233 검증 실패             */
		NRC_MODULE_PUST_ECDSA_K283_SIGN_FAILED,	  /* 자가시험 ECDSA k283 서명 실패             */
		NRC_MODULE_PUST_ECDSA_K283_VERIFY_FAILED, /* 자가시험 ECDSA k283 검증 실패             */
		NRC_MODULE_PUST_ECDSA_B233_SIGN_FAILED,	  /* 자가시험 ECDSA b233 서명 실패		     */
		NRC_MODULE_PUST_ECDSA_B233_VERIFY_FAILED, /* 자가시험 ECDSA b233 검증 실패			 */
		NRC_MODULE_PUST_ECDSA_B283_SIGN_FAILED,	  /* 자가시험 ECDSA b283 서명 실패			 */
		NRC_MODULE_PUST_ECDSA_B283_VERIFY_FAILED, /* 자가시험 ECDSA b283 검증 실패             */
		NRC_MODULE_PUST_ECDSA_P224_SIGN_FAILED,	  /* 자가시험 ECDSA p224 서명 실패	 	    - 1080  */
		NRC_MODULE_PUST_ECDSA_P224_VERIFY_FAILED, /* 자가시험 ECDSA p224 검증 실패			*/
		NRC_MODULE_PUST_ECDSA_P256_SIGN_FAILED,	  /* 자가시험 ECDSA p256 서명 실패             */
		NRC_MODULE_PUST_ECDSA_P256_VERIFY_FAILED, /* 자가시험 ECDSA p256 검증 실패             */

		NRC_MODULE_PUST_ECDH_K233_DERIVE_KEY_FAILED, /* 자가시험 ECDH K233 키 합의 실패		     */
		NRC_MODULE_PUST_ECDH_K283_DERIVE_KEY_FAILED, /* 자가시험 ECDH K283 키 합의 실패           */
		NRC_MODULE_PUST_ECDH_B233_DERIVE_KEY_FAILED, /* 자가시험 ECDH B233 키 합의 실패		     */
		NRC_MODULE_PUST_ECDH_B283_DERIVE_KEY_FAILED, /* 자가시험 ECDH B283 키 합의 실패			 */
		NRC_MODULE_PUST_ECDH_P224_DERIVE_KEY_FAILED, /* 자가시험 ECDH P224 키 합의 실패			 */
		NRC_MODULE_PUST_ECDH_P256_DERIVE_KEY_FAILED, /* 자가시험 ECDH P256 키 합의 실패			 */

		NRC_MODULE_PUST_SEED_GMAC_SIGN_FAILED,	 /* 자가시험 SEED-GMAC 서명 실패		- 1090 */
		NRC_MODULE_PUST_SEED_GMAC_VERIFY_FAILED, /* 자가시험 SEED-GMAC 검증 실패			*/
		NRC_MODULE_PUST_ARIA_GMAC_SIGN_FAILED,	 /* 자가시험 ARIA-GMAC 서명 실패			   */
		NRC_MODULE_PUST_ARIA_GMAC_VERIFY_FAILED, /* 자가시험 ARIA-GMAC 검증 실패			   */
		NRC_MODULE_PUST_LEA_GMAC_SIGN_FAILED,	 /* 자가시험 LEA-GMAC 서명 실패             */
		NRC_MODULE_PUST_LEA_GMAC_VERIFY_FAILED,	 /* 자가시험 LEA-GMAC 검증 실패             */

		NRC_MODULE_PUST_DRBG_INVALID,	   /* 모듈 동작 전 자가시험 난수 발생기 시험 실패	*/
		NRC_MODULE_STATE_UNDEFINED,		   /* 모듈이 미지의 상태임							*/
		NRC_MODULE_STATE_ILLEGAL_CHANGE,   /* 모듈이 허용되지 않은 상태에 있음				*/
		NRC_MODULE_TERMINATED,			   /* 모듈이 종료상태에 있음						*/
		NRC_MODULE_STATE_DISAPPR_ALG,	   /* 현상태에서 허용하지 않는 알고리즘임	- 1100	*/
		NRC_MODULE_INTEGRITY_CHECK_FAILED, /* 모듈 무결성검사에 실패함.				*/
		NRC_MODULE_DRBG_INIT_FAILED,	   /* 엔트로피 수집과 DRBG 초기화 실패				*/
		NRC_MODULE_CST_KEYPAIR_INVALID,	   /* 모듈 조건부 자가시험 키 쌍 일치 시험 실패	*/

		NRC_MODULE_PUST_PBKDF_FAILED, /* 자가시험 PBKDF 검증 실패		- 1104 */
	};

	/*----------------------------------------------------------------------
		블록 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_BLOCKCIPHER_ERROR
	{
		/*SEED*/
		NRC_SEED_ENCRYPT_INIT_FAILED = 2000, /* SEED 암호 초기화 실패       */
		NRC_SEED_DECRYPT_INIT_FAILED,		 /* SEED 암호 초기화 실패      */
		NRC_SEED_PADDING_ERROR,				 /* 입력 데이터의 길이가 블록 크기의 배수가 아님    */
		NRC_SEED_MAC_MISMATCHED,			 /* SEED MAC 값이 일치하지 않음                       */
		NRC_SEED_KEY_SCHEDULE_FAILED,		 /* SEED 키 스케쥴 실패       */
		NRC_SEED_GCM_VERIFY_FAILED,			 /* SEED-GCM MAC 값이 일치하지 않음 */

		/*AES*/
		NRC_AES_ENCRYPT_INIT_FAILED, /* AES 암호 초기화 실패      */
		NRC_AES_DECRYPT_INIT_FAILED, /* AES 암호 초기화 실패      */
		NRC_AES_PADDING_ERROR,		 /* 입력 데이터의 길이가 블록 크기의 배수가 아님   */
		NRC_AES_MAC_MISMATCHED,		 /* AES MAC 값이 일치하지 않음                        */
		NRC_AES_KEY_SCHEDULE_FAILED, /* AES 키 스케쥴 실패     - 2010   */
		NRC_INVALID_AES_KEY_SIZE,	 /* 지정된 AES 키 사이즈가 유효하지 않음 */
		NRC_AES_GCM_VERIFY_FAILED,	 /* AES-GCM MAC 값이 일치하지 않음 */

		/*ARIA*/
		NRC_ARIA_ENCRYPT_INIT_FAILED, /* ARIA 암호 초기화 실패      */
		NRC_ARIA_DECRYPT_INIT_FAILED, /* ARIA 암호 초기화 실패      */
		NRC_ARIA_PADDING_ERROR,		  /* 입력 데이터의 길이가 블록 크기의 배수가 아님    */
		NRC_ARIA_MAC_MISMATCHED,	  /* ARIA MAC 값이 일치하지 않음                       */
		NRC_ARIA_KEY_SCHEDULE_FAILED, /* ARIA 키 스케쥴 실패    */
		NRC_INVALID_ARIA_KEY_SIZE,	  /* 지정된 ARIA 키 사이즈가 유효하지 않음 */
		NRC_ARIA_GCM_VERIFY_FAILED,	  /* ARIA-GCM MAC 값이 일치하지 않음 */

		/*LEA*/
		NRC_LEA_ENCRYPT_INIT_FAILED, /* LEA 암호 초기화 실패   - 2020   */
		NRC_LEA_DECRYPT_INIT_FAILED, /* LEA 암호 초기화 실패      */
		NRC_LEA_PADDING_ERROR,		 /* 입력 데이터의 길이가 블록 크기의 배수가 아님    */
		NRC_LEA_MAC_MISMATCHED,		 /* LEA MAC 값이 일치하지 않음                       */
		NRC_LEA_KEY_SCHEDULE_FAILED, /* LEA 키 스케쥴 실패    */
		NRC_INVALID_LEA_KEY_SIZE,	 /* 지정된 LEA 키 사이즈가 유효하지 않음   */
		NRC_LEA_GCM_VERIFY_FAILED,	 /* LEA-GCM MAC 값이 일치하지 않음 */

		/*PIPO*/
		NRC_PIPO_ENCRYPT_INIT_FAILED, /* PIPO 암호 초기화 실패      */
		NRC_PIPO_DECRYPT_INIT_FAILED, /* PIPO 암호 초기화 실패      */
		NRC_PIPO_PADDING_ERROR,		  /* 입력 데이터의 길이가 블록 크기의 배수가 아님    */
		NRC_PIPO_KEY_SCHEDULE_FAILED, /* PIPO 키 스케쥴 실패    */
		NRC_INVALID_PIPO_KEY_SIZE,	  /* 지정된 PIPO 키 사이즈가 유효하지 않음   */
	};

	/*----------------------------------------------------------------------
	메시지 인증 코드 에러 코드(SHA2, SHA3)
	----------------------------------------------------------------------*/
	enum NSCE_HMAC_ERROR
	{
		NRC_SHA224_HMAC_VERIFY_FAILED = 3000, /* SHA256-HMAC ???? ???? */
		NRC_SHA256_HMAC_VERIFY_FAILED,		  /* SHA256-HMAC ???? ???? */
		NRC_SHA384_HMAC_VERIFY_FAILED,		  /* SHA384-HMAC ???? ???? */
		NRC_SHA512_HMAC_VERIFY_FAILED,		  /* SHA512-HMAC ???? ???? */

		NRC_SHA3_224_HMAC_VERIFY_FAILED, /* SHA3_224-HMAC ???? ???? */
		NRC_SHA3_256_HMAC_VERIFY_FAILED, /* SHA3_256-HMAC ???? ???? */
		NRC_SHA3_384_HMAC_VERIFY_FAILED, /* SHA3_384-HMAC ???? ???? */
		NRC_SHA3_512_HMAC_VERIFY_FAILED, /* SHA3_512-HMAC ???? ???? */

		NRC_HMAC_KEYLENGTH_INVALID, /* HMAC ?????? ??? ????? */
	};

	/*----------------------------------------------------------------------
		타원 곡선 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_ECC_ERROR
	{
		NRC_EC_NUMBER_NOT_SUPPORTED = 4000, /* 지원되지 않는 타원곡선 번호 */
		NRC_ECDH_BASEKEY_EMPTY,				/* ECDH BASEKEY 입력 없음      */
		NRC_ECDH_PEERSKEY_EMPTY,			/* ECDH PEER's KEY 없음        */
		NRC_ECDSA_SIGNATURE_MISMATCHED,		/* ECDSA 서명이 일치하지 않음  */
		NRC_ECC_KEYLENGTH_INVALID,			/* ECC 키길이가 잘못 되었음 */
		NRC_ECDH_DERIVE_KEY_FAILED,			/* ECDH 키 합의 실패 */
	};

	/*----------------------------------------------------------------------
	RSA 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_RSA_ERROR
	{
		NRC_RSA_PRIME_TYPE_NOT_SUPPORTED = 5000, /* ???????? ??? ??????*/
		NRC_RSA_ENCRYPT_FAILED,					 /* RSA ???? ????             */
		NRC_RSA_DECRYPT_FAILED,					 /* RSA ???? ????             */
		NRC_RSA_KEYLENGTH_INVALID,				 /* RSA ?????? ??? ????? */
		NRC_RSA_VERIFY_FAILED,					 /* RSA ???? ???? */
		NRC_RSA_KEY_DECODE_FAILED,				 /* RSA ? ????? ???? */
		NRC_RSA_BITSLENGTH_INVAILD,				 /* RSA bit????? ??? ????? */
	};

	/*----------------------------------------------------------------------
	DILITHIUM 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_DILITHIUM_ERROR
	{
		NRC_DILITHIUM_SIGN_FAILED = 6000,	   /* Dilithium 서명 생성 실패             */
		NRC_DILITHIUM_VERIFY_FAILED,		   /* Dilithium 서명 검증 실패             */
		NRC_DILITHIUM_KEYLENGTH_INVALID,	   /* Dilithium 키길이가 잘못 되었음 */
		NRC_DILITHIUM_SIGNATURE_DECODE_FAILED, /* Dilithium 서명 디코딩 실패 */
		NRC_DILITHIUM_SIGNATURE_MISMATCHED,	   /* Dilithium 서명이 일치하지 않음  */
	};

	/*----------------------------------------------------------------------
	KYBER 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_KYBER_ERROR
	{
		NRC_KYBER_KEYLENGTH_INVALID = 7000, /* KYBER 키길이가 잘못 되었음 */
		NRC_KYBER_KEY_ENCAPSULATE_FAILED,	/* Kyber Encapsulation 실패 */
		NRC_KYBER_KEY_DECAPSULATE_FAILED,	/* Kyber Decapsulation 실패 */
	};

	/*----------------------------------------------------------------------
	FALCON 암호 에러 코드
	----------------------------------------------------------------------*/
	enum NSCE_FALCON_ERROR
	{
		NRC_FALCON_SIGN_FAILED = 8000,	    /* Falcon 서명 생성 실패             */
		NRC_FALCON_VERIFY_FAILED,		    /* Falcon 서명 검증 실패             */
		NRC_FALCON_KEYLENGTH_INVALID,	    /* Falcon 키길이가 잘못 되었음 */
		NRC_FALCON_SIGNATURE_DECODE_FAILED, /* Falcon 서명 디코딩 실패 */
		NRC_FALCON_SIGNATURE_MISMATCHED,	/* Falcon 서명이 일치하지 않음  */
	};

	/***********************************************************************
	Functions
	***********************************************************************/

#ifdef WIN32
#define NT_API __declspec(dllexport)
#else
#define NT_API
#endif

	NT_API NT_BYTE_PTR
	NS_get_errmsg(
		NT_ULONG errorcode);

	NT_API NT_RV
	NS_get_info(
		NT_INFO_PTR pInfo);

	NT_API NT_RV
	NS_clear_object(
		NT_OBJECT_PTR poObject,
		NT_ULONG ulAttrCnt);

	/* key management */
	NT_API NT_RV
	NS_generate_keypair(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPublicKey,
		NT_OBJECT_PTR poPrivateKey);

	NT_API NT_RV
	NS_generate_key(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_derive_key(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poBaseKey,
		NT_OBJECT_PTR poKey);

	/* encryption */
	NT_API NT_RV
	NS_encrypt_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_encrypt(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poData,
		NT_OBJECT_PTR poEncryptedData);

	NT_API NT_RV
	NS_encrypt_update(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPart,
		NT_OBJECT_PTR poEncryptedPart);

	NT_API NT_RV
	NS_encrypt_final(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poLastEncryptedPart);

	/* decryption */
	NT_API NT_RV
	NS_decrypt_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_decrypt(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poEncryptedData,
		NT_OBJECT_PTR poData);

	NT_API NT_RV
	NS_decrypt_update(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poEncryptedPart,
		NT_OBJECT_PTR poPart);

	NT_API NT_RV
	NS_decrypt_final(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poLastPart);

	/* sign */
	NT_API NT_RV
	NS_sign_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_sign(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poData,
		NT_OBJECT_PTR poSignature);

	NT_API NT_RV
	NS_sign_update(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPart);

	NT_API NT_RV
	NS_sign_final(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poSignature);

	/* verify */
	NT_API NT_RV
	NS_verify_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_verify(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poData,
		NT_OBJECT_PTR poSignature);

	NT_API NT_RV
	NS_verify_update(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPart);

	NT_API NT_RV
	NS_verify_final(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poSignature);

	/* random */
	NT_API NT_RV
	NS_seed_random(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poSeed);

	NT_API NT_RV
	NS_generate_random(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poRandom);

	/* message digest */
	NT_API NT_RV
	NS_digest_init(
		NT_CONTEXT_PTR poCtx);

	NT_API NT_RV
	NS_digest(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poData,
		NT_OBJECT_PTR poDigest);

	NT_API NT_RV
	NS_digest_update(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPart);

	NT_API NT_RV
	NS_digest_final(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poDigest);

	NT_API NT_RV
	NS_pbkdf(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poPassword,
		NT_OBJECT_PTR poMasterKey);

	/* KEM */
	NT_API NT_RV
	NS_encapsulate_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_encapsulate(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poData,
		NT_OBJECT_PTR poEncryptedData);

	NT_API NT_RV
	NS_decapsulate_init(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poKey);

	NT_API NT_RV
	NS_decapsulate(
		NT_CONTEXT_PTR poCtx,
		NT_OBJECT_PTR poEncryptedData,
		NT_OBJECT_PTR poSharedSecret);

	/* utility */
	NT_API NT_RV
	NS_hex_dump(
		NT_BYTE_PTR p,
		NT_ULONG sz,
		NT_BYTE_PTR displayStr);

	NT_API NT_RV
	NS_file_hex_dump(
		NT_BYTE_PTR p,
		NT_ULONG sz,
		NT_BYTE_PTR displayStr,
		NT_BYTE_PTR filePath);

	NT_API NT_RV
	NS_table_hex_dump(
		NT_BYTE_PTR p,
		NT_ULONG sz,
		NT_BYTE_PTR displayStr);

	/* CMVP module management */

	NT_API NT_RV
	NS_get_state(
		void);

	NT_API NT_RV
	NS_change_state(
		NT_ULONG module_state);

	NT_API NT_RV
	NS_self_test(
		void);

	NT_API NT_RV
	NS_keypair_valid(NT_CONTEXT_PTR keygenctx,
					 NT_OBJECT_PTR poPrivateKey,
					 NT_OBJECT_PTR poPublicKey);

#ifdef __cplusplus
}
#endif

#endif /* _NSCRYPTO_ */
