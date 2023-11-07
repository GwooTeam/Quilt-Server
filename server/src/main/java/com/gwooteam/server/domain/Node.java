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
    private String ip;

    @NonNull
    @Column(unique = true, length = 10)
    private String nodeID;

    @NonNull
    @Column(unique = true, length = 10)
    private String nodePW;

    @Column(unique = true, length = 10)
    private String nonce;
}
