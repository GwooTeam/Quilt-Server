package com.gwooteam.server.auth;

public interface NodeAuthentication {

    Boolean signKeygen();

    String generateMacKey();
    // 서명 검증
    Boolean verifySign(String pukVal, String dataVal, String signVal);
    // 무결성 검증
    Boolean verifyIntegrity(String macKey, String dataVal, String signVal);

}
