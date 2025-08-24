package com.iotclient.crypto;
import javax.crypto.SecretKey;
public class EncyrptionUtilExample {
    public static void main(String[] args) throws Exception {
        byte[] seed = new byte[32]; // Example seed, replace with r1 from RandomnessExpansionUtils
        new java.security.SecureRandom().nextBytes(seed);

        SecretKey key = EncryptionUtils.deriveKey(seed);
        String passwordHash = "example_password_hash";
        byte[] plaintext = passwordHash.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        byte[] encrypted = EncryptionUtils.encrypt(plaintext, key);
        System.out.println("Encrypted (hex): " + bytesToHex(encrypted));

        byte[] decrypted = EncryptionUtils.decrypt(encrypted, key);
        System.out.println("Decrypted: " + new String(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
