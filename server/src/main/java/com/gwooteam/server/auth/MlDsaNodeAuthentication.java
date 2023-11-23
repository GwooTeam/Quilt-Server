package com.gwooteam.server.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class MlDsaNodeAuthentication implements NodeAuthentication {

    @Value("${dmodule.program.path}")
    private String dmodulePath;

    @Override
    public Boolean keygen() {
        // 임시 하드코딩
        dmodulePath = "./src/main/resources/modules/ML-DSA/dmodule";
        System.out.println("dmodulePath: " + dmodulePath);
        // String pathArg = "--path=" + keyPath;
        String[] command = {dmodulePath, "--keygen"};

        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            // 키 생성 실패 시
            return Boolean.FALSE;
        }

        // 키 생성 성공 시
        return Boolean.TRUE;
    }

    @Override
    public Boolean verifySign(String signPath) {
        // 임시 하드코딩
        dmodulePath = "./src/main/resources/modules/ML-DSA/dmodule";

        String[] command = {dmodulePath, "-v", signPath, "dilithium_key.prk"};
        int exitCode;

        try {
            Process process = Runtime.getRuntime().exec(command);
            exitCode = process.waitFor();

            // 모듈 실행결과가 0이면 성공
            if(exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
        }

        // 예외 발생으로 인한 종료 시
        return Boolean.FALSE;
    }

}
