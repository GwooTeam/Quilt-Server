DROP DATABASE IF EXISTS user_info;
CREATE DATABASE user_info DEFAULT CHARSET=utf8 COLLATE=utf8_bin;

USE user_info;
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id TINYINT NOT NULL AUTO_INCREMENT, 
    hostname VARCHAR(10) NOT NULL,
    ip VARCHAR(15) NOT NULL,
    PRIMARY KEY (id)
) ENGINE=InnODB DEFAULT CHARSET=utf8;

INSERT INTO users (hostname, ip) VALUES ('lee', '111.111.111.111');
INSERT INTO users (hostname, ip) VALUES ('young', '222.222.222.222');
INSERT INTO users (hostname, ip) VALUES ('jun', '333.333.333.333');