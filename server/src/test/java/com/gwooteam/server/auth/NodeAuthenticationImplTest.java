package com.gwooteam.server.auth;

import com.gwooteam.server.integrity.Integrity;
import com.gwooteam.server.integrity.MacIntegrity;
import com.gwooteam.server.sign.DigitalSignature;
import com.gwooteam.server.sign.MldsaDigitalSignature;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

class NodeAuthenticationImplTest {

    DigitalSignature ds = new MldsaDigitalSignature();
    Integrity integrity = new MacIntegrity();
    NodeAuthentication nodeAuthentication = new NodeAuthenticationImpl(ds, integrity);

    @Test
    void verifySign() {
        // given
        String nodeSignPath = "";

        // when
        Boolean res = nodeAuthentication.verifySign("originFile", nodeSignPath);

        // then
        Assertions.assertThat(res).isEqualTo(Boolean.TRUE);
    }

}