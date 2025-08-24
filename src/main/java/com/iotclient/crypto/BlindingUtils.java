package com.iotclient.crypto;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Utility class to blind and unblind elliptic curve points.
 * Uses Bouncy Castle for ECC point operations.
 */
public class BlindingUtils {

    public final ECParameterSpec ecSpec;
    private final SecureRandom random;

    public BlindingUtils() {
        // Add Bouncy Castle Provider if not already added
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        // Use a named curve (e.g., "secp256r1") - can be replaced per your design
        this.ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
        this.random = new SecureRandom();
    }

    /**
     * Blind an ECPoint by multiplying with a random scalar.
     *
     * @param point The original point (e.g., password hashed to curve)
     * @return A BlindedPoint object containing blinded point and the blinding factor.
     */
    public BlindedPoint blind(ECPoint point) {
        BigInteger blindingFactor = randomScalar();
        ECPoint blindedPoint = point.multiply(blindingFactor).normalize();

        return new BlindedPoint(blindedPoint, blindingFactor);
    }

    /**
     * Unblind an ECPoint by multiplying with the modular inverse of the blinding factor.
     *
     * @param blindedPoint The blinded curve point (e.g., signature on blinded point)
     * @param blindingFactor The blinding scalar originally used to blind the point
     * @return The unblinded ECPoint (e.g., signature on original point)
     */
    public ECPoint unblind(ECPoint blindedPoint, BigInteger blindingFactor) {
        BigInteger order = ecSpec.getN();
        BigInteger inv = blindingFactor.modInverse(order);
        return blindedPoint.multiply(inv).normalize();
    }

    /**
     * Generate a secure random scalar within [1, n-1].
     */
    private BigInteger randomScalar() {
        BigInteger n = ecSpec.getN();
        BigInteger k;
        do {
            k = new BigInteger(n.bitLength(), random);
        } while (k.equals(BigInteger.ZERO) || k.compareTo(n) >= 0);
        return k;
    }

    /**
     * Helper class to hold blinded point and factor.
     */
    public static class BlindedPoint {
        private final ECPoint point;
        private final BigInteger blindingFactor;

        public BlindedPoint(ECPoint point, BigInteger blindingFactor) {
            this.point = point;
            this.blindingFactor = blindingFactor;
        }

        public ECPoint getPoint() {
            return point;
        }

        public BigInteger getBlindingFactor() {
            return blindingFactor;
        }
    }
}
