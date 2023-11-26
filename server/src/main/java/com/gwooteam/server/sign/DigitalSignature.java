package com.gwooteam.server.sign;

public interface DigitalSignature {

    public Boolean keygen();

    public Boolean createSign(String filePath);

    public Boolean verifySign(String originFilePath, String SignFilePath);

}
