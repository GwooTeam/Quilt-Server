package com.gwooteam.server.api;

import com.gwooteam.server.domain.Node;
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
@RequiredArgsConstructor
public class NodeApiController {

    private final NodeService nodeService;

    // ServerPubKey
    @PostMapping("/node/requestSvrPubK")
    public ResponseEntity<FetchSvrPubK> enrollNonce () {
        FetchSvrPubK svrPubK = new FetchSvrPubK();
        return ResponseEntity.ok(svrPubK);
    }

    // 임시 Server PubK, PriK 생성 로직
    @Data
    static class FetchSvrPubK {
        private String svrPubK;
        // 사전에 Svr.PubK, Svr.PriK 생성한 후 Fetch해오도록 수정
        public FetchSvrPubK() { this.svrPubK = "alreadyGeneratedSvrPubK";}
    }

    // Nonce
    @PostMapping("/node/{id}/generateNonce")
    public ResponseEntity<SaveNonce> enrollNonce (@PathVariable("id") Long id) {
        String nonce = generateRandom(10);
        nodeService.saveNonce(id, nonce);

        SaveNonce saveNonce = new SaveNonce();
        saveNonce.setNonce(nonce);

        return ResponseEntity.ok(saveNonce);
    }

    @Data
    static class SaveNonce {
        private String nonce;
    }

    private String generateRandom(Integer n) {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder nonce = new StringBuilder();
        Random random = new Random();
//        int length = 10;
        for (int i = 0; i < n; i++) {
            int index = random.nextInt(characters.length());
            nonce.append(characters.charAt(index));
        }
        return nonce.toString();
    }

    // Verify MAC, Sign, PubK(s), PubK(e)
    @PostMapping("/node/{id}/verify")
    public ResponseEntity<Certificates> verify(@PathVariable("id") Long id, @RequestBody @Valid Verify request) {

        VerifyForm verifyForm = new VerifyForm();

        // Save Node PubK_sign, PubK_encrypt
        Node node = nodeService.findOne(id);
        nodeService.savePubKeys(id, request.getNodeEncryptPubK(), request.getNodeSignPubK());

        // request에서 추출
        String fetchNonce = nodeService.findOne(id).getNonce();
        String nodeSign = request.getNodeSign();
        String nodeMac = request.getNodeMac();

        // 검증 결과 저장
        Boolean resultMacVerification = verifyMac(fetchNonce, nodeMac);
        Boolean resultSignVerification = verifySign(fetchNonce, nodeSign);

        // 검증 결과에 따른 Certificate 생성
        if (resultSignVerification == Boolean.TRUE && resultMacVerification == Boolean.TRUE) {
            // Generate Certificates
            Certificates certificates = generateCertificates(request.nodeEncryptPubK, request.nodeSignPubK, request.nodePublicIP);

            // Save Certificates


            // Send Certificates
            return ResponseEntity.ok(certificates);
        } else {
            // BadRequest 전달
            return ResponseEntity.badRequest().build();
        }
    }

    // MAC 인증 로직
    private Boolean verifyMac(String fetchNonce, String nodeMac) {

        // Server 측 MAC 계산
        String serverMac = "";

        if (nodeMac ==  serverMac) {
            return Boolean.TRUE;
        } else {
            return Boolean.FALSE;
        }
    }

    // Sign 인증 로직
    private Boolean verifySign(String fetchNonce, String nodeSign) {

        // Server 측 Sign 계산
        String serverSign = "";

        if (nodeSign ==  serverSign) {
            return Boolean.TRUE;
        } else {
            return Boolean.FALSE;
        }
    }

    private Certificates generateCertificates(String pubK_encrypt, String pubK_sign, String publicIP) {
        Certificates certificates = new Certificates();

        CertificateEncrypt certificateEncrypt = new CertificateEncrypt();
        certificateEncrypt.serialNumber = generateRandom(10);
        certificateEncrypt.pubK_encrypt = pubK_encrypt;
        certificateEncrypt.publicIP = publicIP;

        CertificateSign certificateSign = new CertificateSign();
        certificateSign.serialNumber = generateRandom(10);
        certificateSign.pubK_sign = pubK_sign;
        certificateSign.publicIP = publicIP;

        // 각 Certificate를 하나의 스트링으로 변환


        // Server Private Key로 서명


        // Init Certificates
        certificates.certificateEncrypt = certificateEncrypt;
        certificates.certificateSign = certificateSign;

        return certificates;
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

    }

    @Data
    static class CertificateSign {
        private String serialNumber;
        private String pubK_sign;
        private String publicIP;
    }

    @Data
    static class CertificateEncrypt {
        private String serialNumber;
        private String pubK_encrypt;
        private String publicIP;
    }

    @Data
    static class Certificates {
        // String으로 자료형 전환 예정
        private CertificateEncrypt certificateEncrypt;
        private CertificateSign certificateSign;
    }
}
