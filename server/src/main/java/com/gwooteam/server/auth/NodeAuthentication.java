package com.gwooteam.server.auth;

public interface NodeAuthentication {

    Boolean keygen();
    Boolean verifySign(String signPath);

}
