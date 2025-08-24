package com.iotclient.crypto;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class SecretSharingTest {

    public static void main(String[] args) {
        // Use a 256-bit prime for the finite field (for testing; should be a large safe prime in real use)
        BigInteger prime = new BigInteger("115792089237316195423570985008687907853269984665640564039457584007913129639937"); // 2^256 - 1, a large prime substitute

        SecretSharing secretSharing = new SecretSharing(prime);

        // Secret to share
        BigInteger secret = new BigInteger("1234567890123456789012345678901234567890");
        System.out.println("Original secret: " + secret);

        // Threshold and number of shares
        int threshold = 3;  // minimum shares needed to recover secret
        int totalShares = 5; // total shares generated

        // Generate polynomial with secret as constant term
        BigInteger[] poly = secretSharing.generatePolynomial(secret, threshold);

        // Generate shares
        Map<BigInteger, BigInteger> shares = secretSharing.generateShares(poly, totalShares);
        System.out.println("Shares:");
        shares.forEach((x, y) -> System.out.println("  x=" + x + ", y=" + y));

        // Select 'threshold' number of shares for recovery
        Map<BigInteger, BigInteger> sharesToRecover = new HashMap<>();
        int count = 0;
        for (Map.Entry<BigInteger, BigInteger> entry : shares.entrySet()) {
            sharesToRecover.put(entry.getKey(), entry.getValue());
            count++;
            if (count == threshold) break;
        }

        // Recover secret
        BigInteger recovered = secretSharing.recoverSecret(sharesToRecover);
        System.out.println("Recovered secret: " + recovered);

        // Verify correctness
        System.out.println("Match: " + secret.equals(recovered));
    }
}
