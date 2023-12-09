package com.gwooteam.server.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MlKemDataEncryption implements DataEncryption {

    // @Value("${kmodule.program.path}")
    private final String modulePath = "classpath:modules/ML-KEM/exec/kmodule";

    @Override
    public String encrypt(String keyVal, String dataVal) {
        String[] command = {modulePath, "--encrypt", "-r", "--key=" + keyVal, "--target=" + dataVal};
        System.out.println("encrypt command = " + String.join(" ", command));

        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(command);

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String encryptOutput = readInputStream(inputStream);

            String encVal = extractSubstring(encryptOutput, "enc=", "");

            return encVal;

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule - encrypt");
            return null;
        }

    }

    @Override
    public String decrypt(String keyVal, String encVal) {
        String[] command = {modulePath, "--decrypt", "-r", "--key=" + keyVal, "--target=" + encVal};
        System.out.println("decrypt command = " + String.join(" ", command));

        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(command);

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String encryptOutput = readInputStream(inputStream);

            String decVal = extractSubstring(encryptOutput, "dec=", "");

            return decVal;

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule - encrypt");
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

    private static String extractSubstring(String input, String startPattern, String endPattern) {
        String result = "";
        Pattern regex = Pattern.compile(Pattern.quote(startPattern) + "(.*?)" + Pattern.quote(endPattern));
        Matcher matcher = regex.matcher(input);

        if (matcher.find()) {
            result = matcher.group(1);
        }

        return result;
    }

}
