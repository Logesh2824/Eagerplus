package com.iotclient.crypto;


import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

/**
 * Implements Shamir Secret Sharing
 * - Polynomial generation with random coefficients over a finite field
 * - Share generation by evaluating the polynomial at given x values
 * - Secret reconstruction using Lagrange interpolation
 */
public class SecretSharing {

    private final BigInteger prime;  // Large prime modulus for finite field
    private final SecureRandom random = new SecureRandom();

    /**
     * Constructor requires a prime modulus.
     *
     * @param prime A large prime to define finite field for shares.
     */
    public SecretSharing(BigInteger prime) {
        this.prime = prime;
    }

    /**
     * Generates a random polynomial of degree (threshold-1) with constant term = secret.
     *
     * @param secret    The secret to share (constant term)
     * @param threshold The minimum number of shares needed to reconstruct
     * @return Array of polynomial coefficients, coefficients[0] = secret
     */
    public BigInteger[] generatePolynomial(BigInteger secret, int threshold) {
        BigInteger[] coefficients = new BigInteger[threshold];
        coefficients[0] = secret;

        for (int i = 1; i < threshold; i++) {
            coefficients[i] = randomBigInteger(prime);
        }
        return coefficients;
    }


    public BigInteger evaluatePolynomial(BigInteger[] coefficients, BigInteger x) {
        BigInteger result = BigInteger.ZERO;
        BigInteger powerOfX = BigInteger.ONE;  // x^0 initially

        for (BigInteger coef : coefficients) {
            result = result.add(coef.multiply(powerOfX)).mod(prime);
            powerOfX = powerOfX.multiply(x).mod(prime);
        }
        return result;
    }

    public Map<BigInteger, BigInteger> generateShares(BigInteger[] coefficients, int shareCount) {
        Map<BigInteger, BigInteger> shares = new HashMap<>();
        for (int i = 1; i <= shareCount; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = evaluatePolynomial(coefficients, x);
            shares.put(x, y);
        }
        return shares;
    }

    public BigInteger recoverSecret(Map<BigInteger, BigInteger> shares) {
        BigInteger secret = BigInteger.ZERO;

        for (BigInteger j : shares.keySet()) {
            BigInteger numerator = BigInteger.ONE;
            BigInteger denominator = BigInteger.ONE;

            for (BigInteger m : shares.keySet()) {
                if (!m.equals(j)) {
                    numerator = numerator.multiply(m.negate()).mod(prime);
                    denominator = denominator.multiply(j.subtract(m)).mod(prime);
                }
            }
            BigInteger lagrangeCoefficient = numerator.multiply(denominator.modInverse(prime)).mod(prime);
            secret = secret.add(shares.get(j).multiply(lagrangeCoefficient)).mod(prime);
        }
        return secret;
    }

    private BigInteger randomBigInteger(BigInteger max) {
        BigInteger result;
        do {
            result = new BigInteger(max.bitLength(), random);
        } while (result.compareTo(max) >= 0);
        return result;
    }
}
