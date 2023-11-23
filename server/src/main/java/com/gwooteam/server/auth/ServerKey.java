package com.gwooteam.server.auth;

public class ServerKey {

    // prk, puk, ssk
    private final KeyType keyType;

    // ml-dsa, ml-kem, aes
    private final KeyAlgorithm keyAlgorithm;

    private byte[] keyVal;
    int keyLength;

    public ServerKey(KeyType keyType, KeyAlgorithm keyAlgorithm) {
        this.keyType = keyType;
        this.keyAlgorithm = keyAlgorithm;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public KeyAlgorithm getKeyAlgorithm() {
        return keyAlgorithm;
    }

    public byte[] getKeyVal() {
        return keyVal;
    }

    public void setKeyVal(byte[] keyVal) {
        this.keyVal = keyVal;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(int keyLength) {
        this.keyLength = keyLength;
    }

}
