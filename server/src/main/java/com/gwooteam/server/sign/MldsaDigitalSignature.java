package com.gwooteam.server.sign;

import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;

public class MldsaDigitalSignature implements DigitalSignature {

    @Value("${dmodule.program.path}")
    private String modulePath;

    @Override
    public Boolean keygen() {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-DSA/dmodule";
        System.out.println("dmodulePath: " + modulePath);
        // String pathArg = "--path=" + keyPath;
        String[] command = {modulePath, "--keygen"};

        // command에 전달한 대로 프로그램 실행
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
    public Boolean createSign(String filePath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-DSA/dmodule";
        System.out.println("dmodulePath: " + modulePath);
        // String pathArg = "--path=" + keyPath;
        String[] command = {modulePath, "-s", filePath};

        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }

        return Boolean.TRUE;
    }

    @Override
    public Boolean verifySign(String originFilePath, String signFilePath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-DSA/dmodule";

        String[] command = {modulePath, "-v", originFilePath, signFilePath, "dilithium_key.prk"};
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
