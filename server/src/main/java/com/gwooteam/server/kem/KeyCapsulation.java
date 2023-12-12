package com.gwooteam.server.kem;

public interface KeyCapsulation {

    Boolean keygen();

    String[] encapsulate(String pukVal);

    String decapsulate(String prkVal, String capVal);

}
