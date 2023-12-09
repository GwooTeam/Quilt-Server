package com.gwooteam.server.auth;

public class QuiltKey {

    // prk, puk, sk
    private final KeyType keyType;

    // ml-dsa, ml-kem, aes, mac
    private final KeyAlgorithm keyAlgorithm;

    private String keyVal;
    int keyLength;

    public QuiltKey(KeyType keyType, KeyAlgorithm keyAlgorithm) {
        this.keyType = keyType;
        this.keyAlgorithm = keyAlgorithm;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public KeyAlgorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public String getKeyVal() {
        return keyVal;
    }

    public void setKeyVal(String keyVal) {
        this.keyVal = keyVal;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

}
