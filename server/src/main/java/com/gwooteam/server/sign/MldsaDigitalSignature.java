package com.gwooteam.server.sign;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@RequiredArgsConstructor
public class MldsaDigitalSignature implements DigitalSignature {

    private final NodeRepository nodeRepository;

    // @Value("${dmodule.program.path}") // 이거 application.properties에 넣고싶은데 방법을 모름
    private final String modulePath = "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-DSA/exec/dmodule";

    @Override
    public Boolean keygen() {
        String[] command = {modulePath, "--keygen", "-f"};
        System.out.println("keygen command = " + String.join(" ", command));
        int exitCode = execCmd(command);
        if(exitCode == 0)
            return Boolean.TRUE;
        else
            return Boolean.FALSE;
    }


    @Override // legacy code
    public Boolean createSignFile(String filePath) {
        // 임시 하드코딩
        // modulePath = "./src/main/resources/modules/ML-DSA/exec/dmodule";
        // System.out.println("dmodulePath: " + modulePath);
        String[] command = {modulePath, "-s", "-f", filePath};
        System.out.println("sign command = " + String.join(" ", command));

        int exitCode = execCmd(command);
        if(exitCode == 0)
            return Boolean.TRUE;
        else
            return Boolean.FALSE;
    }


    @Override
    public String createSignStr(String data) {

        // read prk file
        String prkStr;
        Resource resource = new ClassPathResource("modules/ML-DSA/data/dilithium_key.prk");
        try {
            byte[] prkData = FileCopyUtils.copyToByteArray(resource.getInputStream());

            StringBuilder prkStringBuilder = new StringBuilder();
            for(byte b: prkData)
                prkStringBuilder.append(String.format("%02x", b));

            prkStr = prkStringBuilder.toString();

        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        // exec sign()
        String[] command = {modulePath, "-s", "-r", data, prkStr};
        System.out.println("sign command = " + String.join(" ", command));
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-DSA/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String encapOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                String signVal = extractSubstring(encapOutput, "sign=", "");
                return signVal;
            } else {
                System.err.println("Failed to execute mmodule - sign");
                return null;
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute kmodule (exception) - sign");
            return null;
        }

    }


    @Override // legacy code
    public Boolean verifySignFile(Long id, String originFilePath, String signFilePath) {
        // 임시 하드코딩
        // modulePath = "./src/main/resources/modules/ML-DSA/dmodule";
        String prkPath = "classpath:ML-DSA/data/dilithium_key.prk";
        String[] command = {modulePath, "-v", "-f", originFilePath, signFilePath, prkPath};
        System.out.println("verify command = " + String.join(" ", command));
        int exitCode;

        try {
            Process process = Runtime.getRuntime().exec(command);
            exitCode = process.waitFor();
            // 모듈 실행결과가 0이면 성공
            if(exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return Boolean.FALSE;
        }

    }

    @Override
    public Boolean verifySignStr(String pukVal, String originData, String signData) {
        if(pukVal == null) {
            System.err.println("Node의 puk가 없습니다.");
            return Boolean.FALSE;
        }

        // exec dmodule
        String[] command = {modulePath, "-v", "-r", originData, signData, pukVal};
        System.out.println("verify command = " + String.join(" ", command));
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침
            
            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/ML-DSA/exec");
            
            Process process = processBuilder.start();

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String verifyOutput = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            System.out.println("verify stdout: " + verifyOutput);
            if (exitCode == 0) {
                return Boolean.TRUE;
            } else {
                System.err.println("Failed to execute dmodule - verify");
                return Boolean.FALSE;
            }

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute dmodule (exception) - verify");
            return Boolean.FALSE;
        }

    }

    private static int execCmd(String[] command) {
        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(command);
            exitCode = process.waitFor();
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            return 1;
        }
        return exitCode;
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

}
