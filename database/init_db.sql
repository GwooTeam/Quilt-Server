DROP DATABASE IF EXISTS node;
CREATE DATABASE node DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

USE node;
DROP TABLE IF EXISTS node_info;
CREATE TABLE node_info (
    id TINYINT NOT NULL AUTO_INCREMENT,
    nodeID VARCHAR(10) NOT NULL,
    nodePW VARCHAR(10) NOT NULL,
    hostname VARCHAR(10) NOT NULL,
    publicIP VARCHAR(15) NOT NULL,
    nonce VARCHAR(16),
    mk VARCHAR(64),
    serial_number VARCHAR(10),
    encrypt_pubK VARCHAR(9000),
    sign_pubK VARCHAR(9000),
    ssk VARCHAR(64), 
    PRIMARY KEY (id)
) ENGINE=InnODB DEFAULT CHARSET=utf8;

INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('hwang98', 'pbd25q5', 'hwang', '64.19.87.11', '36ced25aeaee6bd6', '2a0b26c2c11796a1', '1', 'qwerqwerqwerqwer', 'qwerqwerqwerqwer');
INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('jaeseok00', 'a1mxafv', 'lee', '32.56.77.22', '470ce8524e32bd63', 'c4106887b1a4b71e', '2', 'qwerqwerqwerqwer', 'qwerqwerqwerqwer');
INSERT INTO node_info (nodeID, nodePW, hostname, publicIP, nonce, mk, serial_number, encrypt_pubK, sign_pubK) VALUES ('han7890', 'p1o4qlyo', 'han', '84.35.12.55',  'd8afc2aa8ec76f1a', '0aa7a73c0e5b9110', '3', 'qwerqwerqwerqwer', 'qwerqwerqwerqwer');
