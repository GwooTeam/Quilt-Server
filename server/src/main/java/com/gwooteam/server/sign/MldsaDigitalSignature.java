package com.gwooteam.server.sign;

import com.gwooteam.server.domain.Node;
import com.gwooteam.server.repository.NodeRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

@RequiredArgsConstructor
public class MldsaDigitalSignature implements DigitalSignature {

    private final NodeRepository nodeRepository;

    // @Value("${dmodule.program.path}") // 이거 application.properties에 넣고싶은데 방법을 모름
    private final String modulePath = "classpath:modules/ML-DSA/exec/dmodule";

    @Override
    public Boolean keygen() {
        // 임시 하드코딩
//        modulePath = "./src/main/resources/modules/ML-DSA/exec/dmodule";
        // modulePath = "classpath:modules/ML-DSA/exec/dmodule";
        // System.out.println("dmodulePath: " + modulePath);

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
            Process process = Runtime.getRuntime().exec(command);

            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();

            String signStr = readInputStream(inputStream);
            return signStr;

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
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
    public Boolean verifySignStr(Long id, String originData, String signData) {
        // puk 값을 읽어와서 String으로 전달
        Node node = nodeRepository.findOne(id);
        String pukStr = node.getSign_pubK();
        // 해당 노드의 puk가 없는 경우
        if(pukStr == null) {
            System.err.println("Node의 puk가 없습니다.");
            return Boolean.FALSE;
        }

        // exec dmodule
        String[] command = {modulePath, "-v", "-r", originData, signData, pukStr};
        System.out.println("verify command = " + String.join(" ", command));
        int exitCode;
        try {
            Process process = Runtime.getRuntime().exec(command);

            InputStream inputStream = process.getInputStream();
            exitCode = process.waitFor();
            if(exitCode == 0)
                return Boolean.TRUE;
            else
                return Boolean.FALSE;

        } catch (IOException | InterruptedException e) {
            e.printStackTrace();
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
        byte[] buffer = new byte[1024];
        int bytesRead;
        StringBuilder result = new StringBuilder();

        while ((bytesRead = inputStream.read(buffer)) != -1) {
            result.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
        }

        return result.toString();
    }

}
