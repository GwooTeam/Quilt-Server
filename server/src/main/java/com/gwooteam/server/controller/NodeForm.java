package com.gwooteam.server.controller;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter // Setter 지양하도록 수정 필요
public class NodeForm {
    private Long id;
    private String hostname;
    private String ip;
    private String nodeID;
    private String nodePW;
    private String nonce;
}
