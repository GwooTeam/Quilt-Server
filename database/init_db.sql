DROP DATABASE IF EXISTS node;
CREATE DATABASE node DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

USE node;
DROP TABLE IF EXISTS node_info;
CREATE TABLE node_info (
    id TINYINT NOT NULL AUTO_INCREMENT,
    nodeID VARCHAR(10) NOT NULL,
    nodePW VARCHAR(10) NOT NULL,
    hostname VARCHAR(10) NOT NULL,
    publicip VARCHAR(15) NOT NULL,
    nonce VARCHAR(20),
    mk VARCHAR(20) NOT NULL,
    serial_number VARCHAR(10),
    encrypt_pubK VARCHAR(20),
    sign_pubK VARCHAR(20),
    PRIMARY KEY (id)
) ENGINE=InnODB DEFAULT CHARSET=utf8;

INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('james010', '1111', 'lee', '111.111.111.111', '', 'firstMK', '', '', '');
INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('james8238', '2222', 'young', '222.222.222.222', '', 'secondMK', '', '', '');
INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('james4239', '3333', 'jun', '333.333.333.333', '', 'thirdMK', '', '', '');