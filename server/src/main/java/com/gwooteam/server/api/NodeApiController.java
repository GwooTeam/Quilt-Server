package com.gwooteam.server.api;

import com.gwooteam.server.service.NodeService;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

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

    @Data
    static class FetchSvrPubK {
        private String svrPubK;
        // 사전에 Svr.PubK, Svr.PriK 생성한 후 Fetch해오도록 수정
        public FetchSvrPubK() { this.svrPubK = "alreadyGeneratedSvrPubK";}
    }

    // Nonce
    @PostMapping("/node/{id}/generateNonce")
    public ResponseEntity<SaveNonce> enrollNonce (@PathVariable("id") Long id) {
        String nonce = generateNonce();
        nodeService.saveNonce(id, nonce);

        SaveNonce saveNonce = new SaveNonce();
        saveNonce.setNonce(nonce);

        return ResponseEntity.ok(saveNonce);
    }

    @Data
    static class SaveNonce {
        private String nonce;
    }

    private String generateNonce() {
        String characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder nonce = new StringBuilder();
        Random random = new Random();
        int length = 10;
        for (int i = 0; i < length; i++) {
            int index = random.nextInt(characters.length());
            nonce.append(characters.charAt(index));
        }
        return nonce.toString();
    }
}
