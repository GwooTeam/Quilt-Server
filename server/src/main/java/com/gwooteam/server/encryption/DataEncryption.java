package com.gwooteam.server.encryption;

public interface DataEncryption {

    Boolean encrypt(String keyPath, String dataPath, String encPath);

    Boolean decrypt(String keyPath, String encPath, String dataPath);

}
