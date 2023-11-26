package com.gwooteam.server.kem;

public interface KeyCapsulation {

    Boolean keygen();

    Boolean encapsulate(String pukPath, String capPath);

    Boolean decapsulate(String prkPath, String capPath, String sskPath);

}
