package com.gwooteam.server.integrity;

public interface Integrity {

    Boolean createHashCode(String filePath);

    Boolean verifyIntegrity(String dataPath, String signPath);

}
