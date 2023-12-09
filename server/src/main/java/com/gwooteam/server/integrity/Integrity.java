package com.gwooteam.server.integrity;

public interface Integrity {

    String macKeygen();

    String createHashCode(String macKey, String dataVal);

    Boolean verifyIntegrity(String macKey, String dataVal, String signVal);

}
