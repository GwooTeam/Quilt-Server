package com.gwooteam.server.integrity;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.io.BufferedReader;
import java.io.InputStreamReader;

public class MacIntegrity implements Integrity {

    // private final String modulePath = "classpath:modules/MAC/exec/mmodule";
    private final String modulePath = "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/MAC/exec/mmodule";

    @Override
    public String macKeygen() {
        String[] command = {modulePath, "--keygen", "-r"};
        System.out.println("keygen command = " + String.join(" ", command));
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침

            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/MAC/exec");

            Process process = processBuilder.start();
            
            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String mKeyStr = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                System.out.println("mk str = " + mKeyStr);
                return extractMKey(mKeyStr);
            } else {
                System.err.println("Failed to execute mmodule - keygen");
                return null;
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute mmodule (exception) - keygen");
            return null;
        }
    }

    @Override
    public String createHashCode(String macKey, String dataVal) {
        // String macKey = getMacKey();

        // exec command
        String[] command = {modulePath, "--hash", "-r", "--key=" + macKey, "--target=" + dataVal};
        System.out.println("hash command = " + String.join(" ", command));
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침

            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/MAC/exec");

            Process process = processBuilder.start();
            
            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            String hashStr = readInputStream(inputStream);

            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                System.out.println("mac hash str = " + hashStr);
                return extractMKey(hashStr);
            } else {
                System.err.println("Failed to execute mmodule - hash");
                return null;
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute mmodule (exception) - hash");
            return null;
        }

    }


    @Override
    public Boolean verifyIntegrity(String macKey, String dataVal, String signVal) {

        // String macKey = getMacKey();

        // exec command
        String[] command = {modulePath, "--verify", "-r", "--key=" + macKey, "--target=" + dataVal, "--result=" + signVal};
        System.out.println("verify command = " + String.join(" ", command));
        int exitCode;
        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true); // 표준 에러를 표준 출력으로 합침

            Map<String, String> env = processBuilder.environment();
            env.put("LD_LIBRARY_PATH", "/home/ubuntu/Quilt-Server/server/src/main/resources/modules/MAC/exec");

            Process process = processBuilder.start();
            
            exitCode = process.waitFor();
            System.out.println("Exit Code: " + exitCode);
            if (exitCode == 0) {
                return Boolean.TRUE;
            } else {
                System.err.println("Failed to execute mmodule - verify");
                return Boolean.FALSE;
            }
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute mmodule (exception) - verify");
            return Boolean.FALSE;
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

    public static String extractMKey(String input) {
        String keyPrefix = "mkey=";
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

    // public static String getResourcePath() {
    //     // "resource/"은 resources 폴더 아래의 resource 폴더를 가리킵니다.
    //     Resource resource = new ClassPathResource("modules/MAC/data/mac_key.mk");

    //     try {
    //         // 리소스의 절대 경로 얻기
    //         return resource.getFile().getAbsolutePath();
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //         return null;
    //     }
    // }


//    public final Boolean keygen() {
//        String[] command = {modulePath, "--keygen", "-f"};
//        System.out.println("keygen command = " + String.join(" ", command));
//        try {
//            // keygen 옵션은 리턴값 없음
//            Process process = Runtime.getRuntime().exec(command);
//            return Boolean.TRUE;
//        } catch (IOException e) {
//            System.err.println("failed to execute mmodule - keygen");
//            return Boolean.FALSE;
//        }
//
//    }



//    private static String getMacKey() {
//        String mKeyStr;
//        Resource resource = new ClassPathResource("modules/MAC/data/mac_key.mk");
//
//        // read mk data
//        try {
//            byte[] mkData = FileCopyUtils.copyToByteArray(resource.getInputStream());
//
//            StringBuilder prkStringBuilder = new StringBuilder();
//            for(byte b: mkData)
//                prkStringBuilder.append(String.format("%02x", b));
//
//            mKeyStr = prkStringBuilder.toString();
//            return mKeyStr;
//        } catch (IOException e) {
//            e.printStackTrace();
//            System.err.println("failed to read mk data.");
//            return null;
//        }
//
//    }

}
