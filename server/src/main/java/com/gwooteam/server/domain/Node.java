package com.gwooteam.server.domain;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import javax.persistence.*;

@Entity
@Table(name="node_info")
@Getter @Setter
public class Node {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NonNull
    @Column(unique = true, length = 10)
    private String hostname;

    @NonNull
    @Column(unique = true, length = 15)
    private String publicIP;

    @NonNull
    @Column(unique = true, length = 10)
    private String nodeID;

    @NonNull
    @Column(unique = true, length = 10)
    private String nodePW;

    // MAC, Nonce Verification
    @Column(unique = true, length = 16)
    private byte[] nonce;

    @NonNull
    @Column(unique = true, length = 16)
    private byte[] mk;

    // Certificate Serial Number
    @Column(unique = true, length = 10)
    private String serialNumber;

    // Node Key
    @Column(unique = true, length = 20)
    private String encryptPubK;

    @Column(unique = true, length = 20)
    private String signPubK;

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

    public String getPublicIP() {
        return publicIP;
    }

    public void setPublicIP(String publicIP) {
        this.publicIP = publicIP;
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

    public byte[] getNonce() {
        return nonce;
    }

    public void setNonce(byte[] nonce) {
        this.nonce = nonce;
    }

    public byte[] getMk() {
        return mk;
    }

    public void setMk(byte[] mk) {
        this.mk = mk;
    }

    public String getSerialNumber() {
        return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
        this.serialNumber = serialNumber;
    }

    public String getEncryptPubK() {
        return encryptPubK;
    }

    public void setEncryptPubK(String encryptPubK) {
        this.encryptPubK = encryptPubK;
    }

    public String getSignPubK() {
        return signPubK;
    }

    public void setSignPubK(String signPubK) {
        this.signPubK = signPubK;
    }
}
