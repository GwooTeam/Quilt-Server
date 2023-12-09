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
    private String nonce;

    @NonNull
    @Column(unique = true, length = 16)
    private String mk;

    // Certificate Serial Number
    @Column(unique = true, length = 10)
    private String serialNumber;

    // Node Key
    @Column(unique = true, length = 20)
    private String encrypt_pubK;

    @Column(unique = true, length = 20)
    private String sign_pubK;

    @Column(unique = true, length = 64)
    private String ssk;


}
