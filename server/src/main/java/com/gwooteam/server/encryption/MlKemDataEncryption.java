package com.gwooteam.server.encryption;

import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;

public class MlKemDataEncryption implements DataEncryption {

    @Value("${kmodule.program.path}")
    private String modulePath;

    @Override
    public Boolean encrypt(String keyPath, String dataPath, String encPath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-KEM/exec/kmodule";
        System.out.println("kmodulePath: " + modulePath);

        String[] command = {modulePath, "--encrypt", "--key=" + keyPath, "--target=" + dataPath, "--result=" + encPath};

        // command에 전달한 대로 프로그램 실행
        try {
            // keygen은 리턴값 없음
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if(exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }

    }

    @Override
    public Boolean decrypt(String keyPath, String encPath, String dataPath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-KEM/exec/kmodule";
        System.out.println("kmodulePath: " + modulePath);

        String[] command = {modulePath, "--decrypt", "--key=" + keyPath, "--target=" + encPath + "--result=" + dataPath};

        // command에 전달한 대로 프로그램 실행
        try {
            // keygen은 리턴값 없음
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if(exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }

    }

}
