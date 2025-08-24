package com.iotclient.crypto;


import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Utility class for AES-GCM encryption and decryption,
 * including symmetric key derivation from a seed.
 */
public class EncryptionUtils {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int AES_KEY_SIZE_BITS = 128; // or 256 if available
    private static final int GCM_IV_LENGTH = 12;      // Recommended 12 bytes for GCM IV
    private static final int GCM_TAG_LENGTH = 128;    // 128 bits authentication tag

    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Derives an AES secret key directly from a seed byte array.
     * For production, use a proper KDF (e.g., HKDF).
     *
     * @param seed input seed keying material
     * @return AES SecretKey
     */
    public static SecretKey deriveKey(byte[] seed) {
        // Use first 16 bytes (128 bits) as AES key; adapt as needed
        byte[] keyBytes = Arrays.copyOf(seed, AES_KEY_SIZE_BITS / 8);
        return new SecretKeySpec(keyBytes, AES_ALGORITHM);
    }

    /**
     * Encrypt plaintext with AES-GCM using the provided key.
     * Generates a random IV for each encryption.
     *
     * @param plaintext data to encrypt
     * @param key       AES secret key
     * @return concatenated IV + ciphertext + tag in a single byte array
     * @throws Exception on encryption error
     */
    public static byte[] encrypt(byte[] plaintext, SecretKey key) throws Exception {
        byte[] iv = new byte[GCM_IV_LENGTH];
        secureRandom.nextBytes(iv);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        byte[] ciphertext = cipher.doFinal(plaintext);

        // Combine IV + ciphertext for transmission/storage
        byte[] encrypted = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encrypted, 0, iv.length);
        System.arraycopy(ciphertext, 0, encrypted, iv.length, ciphertext.length);

        return encrypted;
    }

    /**
     * Decrypt AES-GCM encrypted data.
     * Expects input as IV + ciphertext + tag concatenated.
     *
     * @param encrypted combined IV + ciphertext + tag
     * @param key       AES secret key
     * @return decrypted plaintext
     * @throws Exception on decryption error
     */
    public static byte[] decrypt(byte[] encrypted, SecretKey key) throws Exception {
        byte[] iv = Arrays.copyOfRange(encrypted, 0, GCM_IV_LENGTH);
        byte[] ciphertext = Arrays.copyOfRange(encrypted, GCM_IV_LENGTH, encrypted.length);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        return cipher.doFinal(ciphertext);
    }
}

