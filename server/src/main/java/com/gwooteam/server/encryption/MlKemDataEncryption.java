package com.gwooteam.server.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MlKemDataEncryption implements DataEncryption {

    // @Value("${kmodule.program.path}")
    private final String modulePath = "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec/kmodule";

    @Override
    public String[] encrypt(String keyVal, String dataVal) {
        String[] command = {modulePath, "--encrypt", "-r", "--key=" + keyVal, "--target=" + dataVal};
        System.out.println("encrypt command = " + String.join(" ", command));

        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String encryptOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                // String encVal = extractVal(encryptOutput, "enc=");
                String[] encRes = extractEncWithLength(encryptOutput);
                return encRes;
            } else {
                System.err.println("Failed to execute kmodule - encrypt");
                return null;
            }
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule (exception) - encrypt");
            return null;
        }

    }

    @Override
    public String decrypt(String keyVal, String encVal) {
        String[] command = {modulePath, "--decrypt", "-r", "--key=" + keyVal, "--target=" + encVal};
        System.out.println("decrypt command = " + String.join(" ", command));

        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String encryptOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                String decVal = extractVal(encryptOutput, "dec=");
                return decVal;
            } else {
                System.err.println("Failed to execute kmodule - encrypt");
                return null;
            }
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule (exception) - encrypt");
            return null;
        }

    }

    private static String readInputStream(InputStream inputStream) throws IOException {
        byte[] buffer = new byte[1024];
        int bytesRead;
        StringBuilder result = new StringBuilder();

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            result.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
        }

        return result.toString();
    }

    public static String extractVal(String input, String prefix) {
        int index = input.indexOf(prefix);
    
        if (index != -1) { // Check if the substring is found
            // Extract the substring that comes after prefix
            String extractedKey = input.substring(index + prefix.length());
            return extractedKey;
        } else {
            return null;
        }
    }

    public static String[] extractEncWithLength(String input) {
        String[] result = new String[2];

        // "name=" 다음의 문자열 추출
        int encIndex = input.indexOf("enc=");
        int lengthIndex = input.indexOf("length=");

        if (encIndex != -1 && lengthIndex != -1) {
            result[0] = input.substring(encIndex + 4, lengthIndex);

            // "age=" 이후의 문자열 추출
            result[1] = input.substring(lengthIndex + 7);
        }

        return result;
    }

}
