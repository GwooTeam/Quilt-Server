package com.gwooteam.server.api;

import com.gwooteam.server.auth.Certificates;
import com.gwooteam.server.auth.QuiltKey;
import com.gwooteam.server.service.NodeApiService;
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
import java.util.Arrays;

@RestController
@RequiredArgsConstructor
public class NodeApiController {

    private final NodeService nodeService;
    private final NodeApiService nodeApiService;


    @PostMapping("/node/requestMacKey")
    public ResponseEntity<QuiltKey> getMacKey() {
        QuiltKey key = nodeApiService.getMacKey();
        return ResponseEntity.ok(key);
    }


    // ServerPubKey
    @PostMapping("/node/requestSvrPubK")
    public ResponseEntity<QuiltKey> getServerPubKey() {
        QuiltKey key = nodeApiService.getServerKemPubKey();
        String keyVal = key.getKeyVal();
        return ResponseEntity.ok(key);
    }


    // Nonce
    @PostMapping("/node/{id}/generateNonce")
    public ResponseEntity<SaveNonce> enrollNonce(@PathVariable("id") Long id, @RequestBody EncapData data) {
        String capVal = data.getCapVal();
        System.out.println("controller - capVal = " + capVal);
        String sskVal = nodeApiService.decapsulate(id, capVal);
        System.out.println("controller - sskVal = " + sskVal);

        String nonce = nodeApiService.generateNonce();
        // nodeApiService.saveNonce(id, nonce); repo(db) 코드라 주석처리함.

        // nonce를 암호화해서 전달
        String encNonce = nodeApiService.encryptData(sskVal, nonce);

        // 객체로 만들어서 response
        SaveNonce saveNonce = new SaveNonce();
        saveNonce.setNonce(encNonce);

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


    // http에 리턴할 클래스
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

    @Data
    @Getter @Setter
    static class EncapData {
        private String capVal;
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
