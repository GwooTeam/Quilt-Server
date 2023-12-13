#ifndef _QUILT_MAC_VERIFY_RAW_H_
#define _QUILT_MAC_VERIFY_RAW_H_

/* MAC 키를 활용하여 해시코드를 생성하는 함수 */
int mac_verify_raw(const char* mkey_val, const char* data_val, const char* sign_val);

#endif