package com.gwooteam.server.encryption;

public interface DataEncryption {

    String encrypt(String keyVal, String dataVal);

    String decrypt(String keyVal, String encVal);

}
