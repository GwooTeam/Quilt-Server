package com.gwooteam.server.auth;
import lombok.Getter;

@Getter
public class Certificates {

    private String serialNumber;
    private String publicIP;
    private String kemPuk;
    private String dsaPuk;

    public Certificates(String serialNumber, String publicIP, String kemPuk, String dsaPuk) {
        this.serialNumber = serialNumber;
        this.publicIP = publicIP;
        this.kemPuk = kemPuk;
        this.dsaPuk = dsaPuk;
    }

    public void setKemPuk(String kemPuk) {
        this.kemPuk = kemPuk;
    }

    public void setDsaPuk(String dsaPuk) {
        this.dsaPuk = dsaPuk;
    }

    // private final CertificateEncrypt certificateEncrypt;
    // private final CertificateSign certificateSign;

    // public Certificates(String pubK_sign, String pubK_encrpyt, String publicIP, String dsaSerial, String kemSerial) {
    //     this.certificateSign = new CertificateSign(dsaSerial, pubK_sign, publicIP);
    //     this.certificateEncrypt = new CertificateEncrypt(kemSerial, pubK_sign, publicIP);
    // }

    // public CertificateEncrypt getCertificateEncrypt() {
    //     return certificateEncrypt;
    // }

    // public CertificateSign getCertificateSign() {
    //     return certificateSign;
    // }

    // private static class CertificateSign {
    //     public CertificateSign(String serialNumber, String pubK_sign, String publicIP) {
    //         this.serialNumber = serialNumber;
    //         this.pubK_sign = pubK_sign;
    //         this.publicIP = publicIP;
    //     }

    //     private String serialNumber;
    //     private String pubK_sign;
    //     private String publicIP;
    // }

    // private static class CertificateEncrypt {
    //     public CertificateEncrypt(String serialNumber, String pubK_encrypt, String publicIP) {
    //         this.serialNumber = serialNumber;
    //         this.pubK_encrypt = pubK_encrypt;
    //         this.publicIP = publicIP;
    //     }

    //     private String serialNumber;
    //     private String pubK_encrypt;
    //     private String publicIP;
    // }

}
