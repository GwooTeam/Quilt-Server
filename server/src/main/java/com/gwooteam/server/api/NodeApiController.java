package com.gwooteam.server.api;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.ServerKey;
import com.gwooteam.server.domain.Node;
import com.gwooteam.server.service.NodeApiServiceImpl;
import com.gwooteam.server.service.NodeService;
import lombok.Data;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import javax.validation.Valid;
import java.util.Random;

@RestController
// @RequiredArgsConstructor
public class NodeApiController {

    private final NodeService nodeService;
    private final NodeApiServiceImpl nodeApiService;

    public NodeApiController(NodeService nodeService, NodeApiServiceImpl nodeApiService) {
        this.nodeService = nodeService;
        this.nodeApiService = nodeApiService;
    }

    // ServerPubKey
    @PostMapping("/node/requestSvrPubK")
    public ResponseEntity<ServerKey> getServerPubKey() {
        ServerKey key = nodeApiService.getServerDsaPubKey();
        return ResponseEntity.ok(key);
//        FetchSvrPubK svrPubK = new FetchSvrPubK();
//        return ResponseEntity.ok(svrPubK);
    }


    // Nonce
    @PostMapping("/node/{id}/generateNonce")
    public ResponseEntity<SaveNonce> enrollNonce (@PathVariable("id") Long id) {
        String nonce = nodeApiService.generateNonce(); // generateRandom(10);
        nodeApiService.saveNonce(id, nonce);

        SaveNonce saveNonce = new SaveNonce();
        saveNonce.setNonce(nonce);

        return ResponseEntity.ok(saveNonce);
    }


    // Verify MAC, Sign, PubK(s), PubK(e)
    @PostMapping("/node/{id}/verify")
    public ResponseEntity<Certificates> verify(@PathVariable("id") Long id, @RequestBody @Valid Verify request) {

        VerifyForm verifyForm = new VerifyForm();

        // nodeApiService를 통해 노드가 보낸 sign과 mac을 검증한다.
        String nodeSign = request.getNodeSign();
        String nodeMac = request.getNodeMac();
        Boolean verifyResult = nodeApiService.verifyNode(id, nodeSign, nodeMac);

        // 성공 시 node의 키를 저장하고 인증서를 발급한다.
        if(verifyResult) {
            // Save Node PubK_sign(MLDSA), PubK_encrypt(MLKEM)
            nodeService.savePubKeys(id, request.getNodeEncryptPubK(), request.getNodeSignPubK());

            // 인증서 발급
            Certificates nodeCertificates = nodeApiService.generateCertificates(
                    request.getNodeEncryptPubK(),
                    request.getNodeSignPubK(),
                    request.getNodePublicIP()
            );

            // 인증서 서버 저장 로직은?

            return ResponseEntity.ok(nodeCertificates);
        }
        else {
            return ResponseEntity.badRequest().build();
        }

    }


    // 임시 Server PubK, PriK 생성 로직
//    @Data
//    static class FetchSvrPubK {
//        private String svrPubK;
//        // 사전에 Svr.PubK, Svr.PriK 생성한 후 Fetch해오도록 수정
//        public FetchSvrPubK() { this.svrPubK = "alreadyGeneratedSvrPubK";}
//    }



    @Data
    static class SaveNonce {
        private String nonce;

        public String getNonce() {
            return nonce;
        }

        public void setNonce(String nonce) {
            this.nonce = nonce;
        }

    }

    // 필요 시 Binary -> String 변환 함수


    @Data
    static class Verify {
        private String nodeMac;
        private String nodeSign;
        private String nodeEncryptPubK;
        private String nodeSignPubK;
        // public IP
        private String nodePublicIP;

        public String getNodeMac() {
            return nodeMac;
        }

        public void setNodeMac(String nodeMac) {
            this.nodeMac = nodeMac;
        }

        public String getNodeSign() {
            return nodeSign;
        }

        public void setNodeSign(String nodeSign) {
            this.nodeSign = nodeSign;
        }

        public String getNodeEncryptPubK() {
            return nodeEncryptPubK;
        }

        public void setNodeEncryptPubK(String nodeEncryptPubK) {
            this.nodeEncryptPubK = nodeEncryptPubK;
        }

        public String getNodeSignPubK() {
            return nodeSignPubK;
        }

        public void setNodeSignPubK(String nodeSignPubK) {
            this.nodeSignPubK = nodeSignPubK;
        }

        public String getNodePublicIP() {
            return nodePublicIP;
        }

        public void setNodePublicIP(String nodePublicIP) {
            this.nodePublicIP = nodePublicIP;
        }

    }

//    @Data
//    static class CertificateSign {
//        private String serialNumber;
//        private String pubK_sign;
//        private String publicIP;
//    }
//
//    @Data
//    static class CertificateEncrypt {
//        private String serialNumber;
//        private String pubK_encrypt;
//        private String publicIP;
//    }
//
//    @Data
//    static class Certificates {
//        // String으로 자료형 전환 예정
//        private CertificateEncrypt certificateEncrypt;
//        private CertificateSign certificateSign;
//    }

}
