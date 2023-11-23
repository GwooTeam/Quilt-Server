package com.gwooteam.server.auth;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class MlDsaNodeAuthenticationTest {

    NodeAuthentication nodeAuthentication = new MlDsaNodeAuthentication();

    @Test
    void verifySign() {
        // given
        String nodeSignPath = "";

        // when
        Boolean res = nodeAuthentication.verifySign(nodeSignPath);

        // then
        Assertions.assertThat(res).isEqualTo(Boolean.TRUE);
    }

}