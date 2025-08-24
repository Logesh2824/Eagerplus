package com.iotclient.crypto;
import org.bouncycastle.math.ec.ECPoint;

public class Example {
    public static void main(String[] args) {
        BlindingUtils blindingUtils = new BlindingUtils();

        // Simulate a password hashed point for demo (use actual HashToCurve in real)
        ECPoint passwordPoint = blindingUtils.ecSpec.getG();

        // Blind the password point
        BlindingUtils.BlindedPoint blinded = blindingUtils.blind(passwordPoint);
        System.out.println("Blinded point: " + blinded.getPoint());
        System.out.println("Blinding factor: " + blinded.getBlindingFactor().toString(16));

        // Later, unblind the point
        ECPoint unblinded = blindingUtils.unblind(blinded.getPoint(), blinded.getBlindingFactor());
        System.out.println("Unblinded point: " + unblinded);

        // unblinded should equal original passwordPoint (for correct ops)
        System.out.println("Matches original: " + unblinded.equals(passwordPoint));
    }
}
