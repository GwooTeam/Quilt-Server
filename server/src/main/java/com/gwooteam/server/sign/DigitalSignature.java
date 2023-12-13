package com.gwooteam.server.sign;

public interface DigitalSignature {

    public Boolean keygen();

    public Boolean createSignFile(String filePath);

    public String createSignStr(String data);

    public Boolean verifySignFile(Long id, String originFilePath, String SignFilePath);

    public Boolean verifySignStr(String pukVal, String originData, String signData);

}
