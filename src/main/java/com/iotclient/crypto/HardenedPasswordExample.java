package com.iotclient.crypto;
import org.bouncycastle.math.ec.ECPoint;
public class HardenedPasswordExample {
    public static void main(String[] args) {
        BlindingUtils blindingUtils = new BlindingUtils();

        // Example: Start with a dummy password point (normally output from hashToCurve)
        ECPoint passwordPoint = blindingUtils.ecSpec.getG();

        // Blind point, generate blinding factor
        BlindingUtils.BlindedPoint blinded = blindingUtils.blind(passwordPoint);

        // Simulate server signature on blinded point as just the blinded point here for demonstration
        ECPoint blindSignature = blinded.getPoint();

        // Client unblinds the signature point
        ECPoint unblindedSignature = blindingUtils.unblind(blindSignature, blinded.getBlindingFactor());

        String password = "myStrongPassword123";

        // Generate hardened password
        byte[] hardenedPw = HardenedPasswordUtils.generateHardenedPassword(unblindedSignature, password);

        System.out.println("Hardened password (hex): " + bytesToHex(hardenedPw));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
