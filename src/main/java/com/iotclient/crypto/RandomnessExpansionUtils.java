package com.iotclient.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Utility class to perform deterministic randomness expansion from hardened password.
 *
 * Expands an input keying material (hardened password) into multiple cryptographic seeds.
 */
public class RandomnessExpansionUtils {

    private static final String HMAC_ALGORITHM = "HmacSHA256";

    /**
     * Expands the input keying material (IKM) into three pseudorandom values r1, r2, r3 each 32 bytes.
     *
     * @param ikm input keying material (hardened password)
     * @return a 2D byte array, with three 32-byte arrays (r1, r2, r3)
     */
    public static byte[][] expand(byte[] ikm) {
        byte[] salt = "EAGERPlus-RandomnessExpand".getBytes(StandardCharsets.UTF_8);
        byte[] prk = hkdfExtract(salt, ikm);

        byte[][] outputs = new byte[3][];
        outputs[0] = hkdfExpand(prk, (byte) 1);
        outputs[1] = hkdfExpand(prk, (byte) 2);
        outputs[2] = hkdfExpand(prk, (byte) 3);

        return outputs;
    }

    // HKDF extract step: PRK = HMAC(salt, IKM)
    private static byte[] hkdfExtract(byte[] salt, byte[] ikm) {
        return hmacSha256(salt, ikm);
    }

    // HKDF expand step (generates 32-byte output block)
    private static byte[] hkdfExpand(byte[] prk, byte info) {
        byte[] data = new byte[1];
        data[0] = info;
        // T(1) = HMAC(PRK, info || counter)
        return hmacSha256(prk, data);
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALGORITHM);
            mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("Error in HMAC-SHA256", e);
        }
    }
}
