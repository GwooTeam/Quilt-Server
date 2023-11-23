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

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getNodeID() {
        return nodeID;
    }

    public void setNodeID(String nodeID) {
        this.nodeID = nodeID;
    }

    public String getNodePW() {
        return nodePW;
    }

    public void setNodePW(String nodePW) {
        this.nodePW = nodePW;
    }

    public String getNonce() {
        return nonce;
    }

    public void setNonce(String nonce) {
        this.nonce = nonce;
    }

}
