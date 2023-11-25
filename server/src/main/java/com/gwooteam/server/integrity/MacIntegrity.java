package com.gwooteam.server.integrity;

import java.io.IOException;

public class MacIntegrity implements Integrity {

    private String modulePath;
    private String keyPath;

    @Override
    public Boolean createHashCode(String filePath) {
        modulePath = "./src/main/resources/modules/MAC/exec/mmodule";
        keyPath = "./src/main/resources/modules/MAC/exec/mac_key.mk";

        String[] command = {modulePath, "--sign", "--key=" + keyPath, "--target=" + filePath};

        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if (exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            return Boolean.FALSE;
        }

    }


    @Override
    public Boolean verifyIntegrity(String dataPath, String signPath) {
        modulePath = "./src/main/resources/modules/MAC/exec/mmodule";
        keyPath = "./src/main/resources/modules/MAC/exec/mac_key.mk";

        String[] command = {modulePath, "--verify", "--key=" + keyPath, "--target=" + dataPath, "--result=" + signPath};

        try {
            Process process = Runtime.getRuntime().exec(command);
            int exitCode = process.waitFor();
            if (exitCode == 0) return Boolean.TRUE;
            else return Boolean.FALSE;
        } catch (IOException | InterruptedException e) {
            return Boolean.FALSE;
        }

    }

    public final Boolean keygen() {
        modulePath = "./src/main/resources/modules/MAC/exec/mmodule";

        String[] command = {modulePath, "--keygen"};

        try {
            // keygen 옵션은 리턴값 없음
            Process process = Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            return Boolean.FALSE;
        }

        return Boolean.TRUE;

    }

}
