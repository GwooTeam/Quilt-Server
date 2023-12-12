package com.gwooteam.server.auth;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.integrity.Integrity;
import com.gwooteam.server.repository.NodeRepository;
import com.gwooteam.server.sign.DigitalSignature;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class NodeAuthenticationImpl implements NodeAuthentication {

    private final NodeRepository nodeRepository;

    private final DigitalSignature ds;

    private final Integrity integrity;

    @Override
    public Boolean signKeygen() {
        return ds.keygen();
    }

    @Override
    public String generateMacKey() {
        return integrity.macKeygen();
    }

    @Override
    public Boolean verifySign(String pukVal, String dataVal, String signVal) {
        return ds.verifySignStr(pukVal, dataVal, signVal);
    }

    @Override
    public Boolean verifyIntegrity(String macKey, String dataVal, String signVal) {
        // Node node = nodeRepository.findOne(id);
        return integrity.verifyIntegrity(macKey, dataVal, signVal);
    }

}
