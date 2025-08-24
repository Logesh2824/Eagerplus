package com.iotclient.crypto;
import org.bouncycastle.math.ec.ECPoint;
public class RandomUtilsExample {
    public static byte[] hexStringToByteArray(String hex) {
        int length = hex.length();
        if (length % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        byte[] data = new byte[length / 2];
        for (int i = 0; i < length; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    public static void main(String[] args) {
        byte[] hardenedPassword= hexStringToByteArray("240ff0f86aa107ba7472c197a0c784d649e67675e2a853d98a9630f44b88bfdc");

        byte[][] seeds = RandomnessExpansionUtils.expand(hardenedPassword);

        System.out.println("r1: " + bytesToHex(seeds[0]));
        System.out.println("r2: " + bytesToHex(seeds[1]));
        System.out.println("r3: " + bytesToHex(seeds[2]));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

}
