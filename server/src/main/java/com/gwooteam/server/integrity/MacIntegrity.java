package com.gwooteam.server.integrity;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public class MacIntegrity implements Integrity {

    private final String modulePath = "classpath:modules/MAC/exec/mmodule";

    @Override
    public String macKeygen() {
        String[] command = {modulePath, "--keygen", "-r"};
        System.out.println("keygen command = " + String.join(" ", command));
        int exitCode;
        try {
            // keygen 옵션은 리턴값 없음
            Process process = Runtime.getRuntime().exec(command);
            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String hashStr = readInputStream(inputStream);
            return hashStr;
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute mmodule - keygen");
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
            Process process = Runtime.getRuntime().exec(command);

            // 실행한 프로세스의 표준 출력을 받아온다.
            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String hashStr = readInputStream(inputStream);
            return hashStr;
        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
            System.err.println("failed to execute mmodule - hashcode");
            return null;
        }

    }


    @Override
    public Boolean verifyIntegrity(String macKey, String dataVal, String signVal) {

        // String macKey = getMacKey();

        // exec command
        String[] command = {modulePath, "--verify", "-r", "--key=" + macKey, "--target=" + dataVal, "--result=" + signVal};
        System.out.println("verify command = " + String.join(" ", command));

        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if (exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            System.err.println("failed to execute mmodule - verify");
            return Boolean.FALSE;
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
