package com.iotclient.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.math.ec.ECPoint;

/**
 * Utility class for generating the hardened password
 * by hashing the signature point concatenated with the original password.
 */
public class HardenedPasswordUtils {

    /**
     * Generate hardened password from the signature point and password string.
     * @param signaturePoint The unblinded signature EC point
     * @param password The original password string
     * @return hardened password bytes (SHA-256 digest)
     */
    public static byte[] generateHardenedPassword(ECPoint signaturePoint, String password) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");

            // Encode ECPoint to bytes (compressed form)
            byte[] sigBytes = signaturePoint.getEncoded(true);

            // Get password bytes UTF-8
            byte[] passwordBytes = password.getBytes(StandardCharsets.UTF_8);

            // Concatenate signature bytes + password bytes
            byte[] combined = new byte[sigBytes.length + passwordBytes.length];
            System.arraycopy(sigBytes, 0, combined, 0, sigBytes.length);
            System.arraycopy(passwordBytes, 0, combined, sigBytes.length, passwordBytes.length);

            // Hash combined data
            return sha256.digest(combined);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 is not available", e);
        }
    }
}
