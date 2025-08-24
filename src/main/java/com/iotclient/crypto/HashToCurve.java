package com.iotclient.crypto;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.security.MessageDigest;

public class HashToCurve {

    private final Pairing pairing;

    public HashToCurve() {
        // Disable native PBC (no need for libpbc.dll)


        // Load curve parameters file (must be in resources/params/)
        pairing = PairingFactory.getPairing("params/a.properties");
    }

    /**
     * Maps a password string to a point on the elliptic curve
     */
    public Element mapToPoint(String password) throws Exception {
        // SHA-256 hash of password
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(password.getBytes());

        // Map hash to point in G1
        return pairing.getG1().newElement().setFromHash(hash, 0, hash.length);
    }

    public static void main(String[] args) throws Exception {
        PairingFactory.getInstance().setUsePBCWhenPossible(false);
        HashToCurve htc = new HashToCurve();

        String password = "myStrongPassword123";
        Element point = htc.mapToPoint(password);

        System.out.println("Password mapped to curve point: " + point);
    }
}
