package com.gwooteam.server.auth;

import com.gwooteam.server.integrity.Integrity;
import com.gwooteam.server.sign.DigitalSignature;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class NodeAuthenticationImpl implements NodeAuthentication {

    private final DigitalSignature ds;

    private final Integrity integrity;

    @Override
    public Boolean signKeygen() {
        return ds.keygen();
    }

    @Override
    public Boolean verifySign(String originFilePath, String signFilePath) {
        return ds.verifySign(originFilePath, signFilePath);
    }

    @Override
    public Boolean verifyIntegrity(String originFilePath, String signFilePath) {
        return integrity.verifyIntegrity(originFilePath, originFilePath);
    }

}
