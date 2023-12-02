#ifndef _QUILT_DILITHIUM_RAW_H_
#define _QUILT_DILITHIUM_RAW_H_

/**
 * PQC 예제 코드(간소화 버전)
 * 임의의 옵션 설정 없이 기본 옵션만으로 암호 알고리즘을 구성한다.
 */
void dilithium_keygen_raw();
void dilithium_sign_raw(const char* data_val, const char* prk_val);
int dilithium_verify_raw(const char* data_val, const char* sign_val, const char* puk_val);

#endif /* _EXAMPLE_H_ */
