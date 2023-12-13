package com.gwooteam.server.kem;

import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
public class MlKemKeyCapsulation implements KeyCapsulation{

    private final NodeRepository nodeRepository;

    // @Value("${kmodule.program.path}")
    private final String modulePath = "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec/kmodule";

    @Override
    public Boolean keygen() {
        String[] command = {modulePath, "--keygen", "-f"};
        System.out.println("keygen command = " + String.join(" ", command));

        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(command);
            exitCode = process.waitFor();

            if(exitCode == 0)
                return Boolean.TRUE;
            else
                return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute kmodule - keygen");
            return Boolean.FALSE;
        }

    }

    @Override
    public String[] encapsulate(String pukVal) {

        String[] command = {modulePath, "--encap", "-r", "--key=" + pukVal};
        System.out.println("encap command = " + String.join(" ", command));

        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String encapOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                String capVal = extractSubstring(encapOutput, "encapsulated=", "ssk=");
                String sskVal = extractSubstring(encapOutput, "ssk=", "");
                return new String[] {capVal, sskVal};
            } else {
                System.err.println("Failed to execute kmodule - encap");
                return null;
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule (exception) - encap");
            return null;
        }

    }

    @Override
    public String decapsulate(String prkVal, String capVal) {
        String[] command = {modulePath, "--decap", "-r", "--key=" + prkVal, "--target=" + capVal};
        System.out.println("decap command = " + String.join(" ", command));

        // command에 전달한대로 프로그램 실행
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-KEM/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String encapOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                String sskVal = extractSsk(encapOutput);
                // System.out.println("decap ssk: " + sskVal);
                return sskVal;
            } else {
                System.err.println("Failed to execute kmodule - decap");
                return null;
            }
            
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule (exception) - decap");
            return null;
        }

    }


    private static String readInputStream(InputStream inputStream) throws IOException {
        StringBuilder result = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream))) {
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line);
            }
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

    public static String extractSsk(String input) {
        String keyPrefix = "ssk=";
        int index = input.indexOf(keyPrefix);
    
        if (index != -1) { // Check if the substring is found
            // Extract the substring that comes after "mkey="
            String extractedKey = input.substring(index + keyPrefix.length());
            return extractedKey;
        } else {
            // "mkey=" not found in the input string
            return null;
        }
    }


}
