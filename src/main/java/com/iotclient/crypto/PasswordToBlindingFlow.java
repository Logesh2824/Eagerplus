package com.iotclient.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Map;

/**
 * Converts password to ECPoint and calls BlindingUtils to blind and unblind
 * Includes detailed debugging prints to trace execution.
 */
public class PasswordToBlindingFlow {

    private final ECParameterSpec ecSpec;
    private final BlindingUtils blindingUtils;

    public PasswordToBlindingFlow() {
        this.ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        this.blindingUtils = new BlindingUtils();
    }

    public void run(String password) {
        try {
            System.out.println("Starting password to point mapping...");
            ECPoint passwordPoint = mapPasswordToPoint(password);
            System.out.println("Password mapped to point: " + pointToString(passwordPoint));

            System.out.println("Blinding point...");
            BlindingUtils.BlindedPoint blinded = blindingUtils.blind(passwordPoint);
            System.out.println("Blinded point: " + pointToString(blinded.getPoint()));
            System.out.println("Blinding factor (hex): " + blinded.getBlindingFactor().toString(16));

            System.out.println("Unblinding point...");
            ECPoint unblinded = blindingUtils.unblind(blinded.getPoint(), blinded.getBlindingFactor());
            System.out.println("Unblinded point: " + pointToString(unblinded));

            System.out.println("Check if unblinded matches original: " + unblinded.equals(passwordPoint));
            byte[] hardenedPassword = HardenedPasswordUtils.generateHardenedPassword(unblinded, password);
            System.out.println("Hardened Password (hex): " + bytesToHex(hardenedPassword));
            byte[][] seeds = RandomnessExpansionUtils.expand(hardenedPassword);
            System.out.println("r1 seed: " + bytesToHex(seeds[0]));
            System.out.println("r2 seed: " + bytesToHex(seeds[1]));
            System.out.println("r3 seed: " + bytesToHex(seeds[2]));

            SecretKey aesKey = EncryptionUtils.deriveKey(seeds[0]);  // r1 seed
            byte[] passwordHash = hashPassword(password) ; // your password hash bytes, e.g., SHA-256 of password

            byte[] encryptedPasswordHash = EncryptionUtils.encrypt(passwordHash, aesKey);
            System.out.println("Encrypted password hash (hex): " + bytesToHex(encryptedPasswordHash));

            BigInteger prime = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639937"); // Same prime as in SecretSharing class
            BigInteger secret = new BigInteger(1, seeds[0]); // r1 seed as secret

            int threshold = 3; // e.g. minimum shares required
            int totalShares = 5; // e.g. total shares to be generated

            SecretSharing secretSharing = new SecretSharing(prime);
            BigInteger[] polynomial = secretSharing.generatePolynomial(secret, threshold);
            Map<BigInteger, BigInteger> shares = secretSharing.generateShares(polynomial, totalShares);

// Debug print shares
            for (Map.Entry<BigInteger, BigInteger> entry : shares.entrySet()) {

                System.out.printf("Share %s: %s%n", entry.getKey(), entry.getValue());
            }

        } catch (Exception ex) {
            System.err.println("Error during password to blinding flow: " + ex.getMessage());
            ex.printStackTrace();
        }
    }
    private static byte[] hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(password.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }
    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    // Map password to valid ECPoint by hashing and searching for valid points
    private ECPoint mapPasswordToPoint(String password) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(password.getBytes(StandardCharsets.UTF_8));
        BigInteger prime = ecSpec.getCurve().getField().getCharacteristic();
        BigInteger x = new BigInteger(1, hash).mod(prime);

        ECPoint point = null;
        int attempts = 0;

        // Try y sign true/false to find valid point, increment x if invalid
        while (attempts < 1000) { // add upper bound to avoid infinite loops
            try {
                point = ecSpec.getCurve().decodePoint(getCompressedPointBytes(x, true));
                if (point != null && !point.isInfinity()) {
                    System.out.println("Found valid point on try #" + attempts + " (yBit=true)");
                    return point.normalize();
                }
            } catch (Exception ignored) {}

            try {
                point = ecSpec.getCurve().decodePoint(getCompressedPointBytes(x, false));
                if (point != null && !point.isInfinity()) {
                    System.out.println("Found valid point on try #" + attempts + " (yBit=false)");
                    return point.normalize();
                }
            } catch (Exception ignored) {}

            x = x.add(BigInteger.ONE).mod(prime);
            attempts++;
        }

        throw new IllegalArgumentException("Cannot find valid EC point from password hash after 1000 attempts");
    }

    // Build compressed point byte array (0x02 or 0x03 + x_bytes)
    private byte[] getCompressedPointBytes(BigInteger x, boolean yBit) {
        byte prefix = (byte) (yBit ? 0x02 : 0x03);
        byte[] xBytes = x.toByteArray();

        // BigInteger.toByteArray() may add a leading zero for sign; strip it if present
        if (xBytes[0] == 0) {
            byte[] tmp = new byte[xBytes.length - 1];
            System.arraycopy(xBytes, 1, tmp, 0, tmp.length);
            xBytes = tmp;
        }

        byte[] compressed = new byte[xBytes.length + 1];
        compressed[0] = prefix;
        System.arraycopy(xBytes, 0, compressed, 1, xBytes.length);
        return compressed;
    }


    // Nicely formatted ECPoint print
    private String pointToString(ECPoint p) {
        if (p == null || p.isInfinity()) {
            return "Point(INFINITY)";
        }
        return "(" + p.getAffineXCoord().toBigInteger().toString(16) + ", " +
                p.getAffineYCoord().toBigInteger().toString(16) + ")";
    }

    public static void main(String[] args) {
        new PasswordToBlindingFlow().run("Password@123");
    }
}
