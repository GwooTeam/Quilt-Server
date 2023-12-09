package com.gwooteam.server.kem;

import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
public class MlKemKeyCapsulation implements KeyCapsulation{

    private final NodeRepository nodeRepository;

    // @Value("${kmodule.program.path}")
    private final String modulePath = "classpath:modules/ML-KEM/exec/kmodule";

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
            Process process = Runtime.getRuntime().exec(command);

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String encapOutput= readInputStream(inputStream);

            String capVal = extractSubstring(encapOutput, "cap=", "ssk=");
            String sskVal = extractSubstring(encapOutput, "ssk=", "");

            return new String[] {capVal, sskVal};

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule - encap");
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
            Process process = Runtime.getRuntime().exec(command);

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String encapOutput= readInputStream(inputStream);

            return extractSubstring(encapOutput, "encapsulated=", "ssk=");

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule - decap");
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
