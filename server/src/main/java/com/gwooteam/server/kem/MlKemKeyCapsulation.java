package com.gwooteam.server.kem;

import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;

public class MlKemKeyCapsulation implements KeyCapsulation{

    @Value("${kmodule.program.path}")
    private String modulePath;

    @Override
    public Boolean keygen() {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-KEM/exec/kmodule";
        System.out.println("kmodulePath: " + modulePath);

        String[] command = {modulePath, "--keygen"};

        // command에 전달한 대로 프로그램 실행
        try {
            // keygen은 리턴값 없음
            Process process = Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }

        return Boolean.TRUE;
    }

    @Override
    public Boolean encapsulate(String pukPath, String capPath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-KEM/exec/kmodule";
        System.out.println("kmodulePath: " + modulePath);

        String[] command = {modulePath, "--encap", "--key=" + pukPath, "--result=" + capPath};

        // command에 전달한대로 프로그램 실행
        try {
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
    public Boolean decapsulate(String prkPath, String capPath, String sskPath) {
        // 임시 하드코딩
        modulePath = "./src/main/resources/modules/ML-KEM/exec/kmodule";
        System.out.println("kmodulePath: " + modulePath);

        String[] command = {modulePath, "--decap", "--key=" + prkPath, "--target=" + capPath, "--result=" + sskPath};

        // command에 전달한대로 프로그램 실행
        try {
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
