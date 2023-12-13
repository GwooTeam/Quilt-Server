#ifndef _QUILT_MAC_SIGN_RAW_H_
#define _QUILT_MAC_SIGN_RAW_H_

/* MAC 키를 활용하여 해시코드를 생성하는 함수 */
int mac_sign_raw(const char* mkey_val, const char* data_val);

#endif