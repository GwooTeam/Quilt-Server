package com.gwooteam.server.api;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class VerifyForm {
    private Long id;
    private String nodeMac;
    private String nodeSign;
    private String nodeEncryptionPubK;
    private String nodeSignPubK;
}
