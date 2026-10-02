package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import javacard.framework.Applet;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;

/**
 * Helpers for EMV protocol tests: hex coding, reference cryptography and APDU exchange with the simulated card.
 */
final class EmvTestUtil {

    static final BigInteger ICC_PUBLIC_EXPONENT = BigInteger.valueOf(3);

    private EmvTestUtil() {
    }

    static byte[] hex(String data) {
        String compact = data.replace(" ", "");
        byte[] result = new byte[compact.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    static byte[] concat(byte[]... arrays) {
        int length = 0;
        for (byte[] array : arrays) {
            length += array.length;
        }

        byte[] result = new byte[length];
        int offset = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, offset, array.length);
            offset += array.length;
        }
        return result;
    }

    static byte[] sha1(byte[]... arrays) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-1").digest(concat(arrays));
    }

    static byte[] des(int mode, byte[] key, byte[] data) throws GeneralSecurityException {
        String algorithm = (key.length == 8) ? "DES" : "DESede";
        byte[] cipherKey = key;
        if (key.length == 16) {
            // K1 || K2 || K1
            cipherKey = concat(key, Arrays.copyOfRange(key, 0, 8));
        }

        Cipher cipher = Cipher.getInstance(algorithm + "/ECB/NoPadding");
        cipher.init(mode, new SecretKeySpec(cipherKey, algorithm));
        return cipher.doFinal(data);
    }

    /**
     * Application Cryptogram Session Key, EMV Book 2 A1.3.1 Common Session Key Derivation Option.
     */
    static byte[] deriveSessionKey(byte[] masterKey, byte[] diversification) throws GeneralSecurityException {
        byte[] f1 = Arrays.copyOf(diversification, 8);
        byte[] f2 = Arrays.copyOf(diversification, 8);
        f1[2] = (byte) 0xF0;
        f2[2] = (byte) 0x0F;
        return des(Cipher.ENCRYPT_MODE, masterKey, concat(f1, f2));
    }

    /**
     * ISO/IEC 7816-4 padding: '80' followed by '00' bytes to a multiple of 8 bytes.
     */
    static byte[] pad(byte[] data) {
        return Arrays.copyOf(concat(data, hex("80")), (data.length / 8 + 1) * 8);
    }

    /**
     * ISO/IEC 9797-1 MAC Algorithm 3 with padding method 2, EMV Book 2 A1.2.1.
     */
    static byte[] retailMac(byte[] sessionKey, byte[] message) throws GeneralSecurityException {
        return macAlgorithm3(sessionKey, pad(message));
    }

    /**
     * ISO/IEC 9797-1 MAC Algorithm 3 over already padded data, EMV Book 2 A1.2.1 step 3.
     */
    static byte[] macAlgorithm3(byte[] sessionKey, byte[] padded) throws GeneralSecurityException {
        byte[] keyLeft = Arrays.copyOfRange(sessionKey, 0, 8);
        byte[] keyRight = Arrays.copyOfRange(sessionKey, 8, 16);

        byte[] block = new byte[8];
        for (int offset = 0; offset < padded.length; offset += 8) {
            for (int i = 0; i < 8; i++) {
                block[i] ^= padded[offset + i];
            }
            block = des(Cipher.ENCRYPT_MODE, keyLeft, block);
        }

        return des(Cipher.ENCRYPT_MODE, keyLeft, des(Cipher.DECRYPT_MODE, keyRight, block));
    }

    static String toHex(byte[] data) {
        StringBuilder result = new StringBuilder();
        for (byte b : data) {
            result.append(String.format("%02X ", b));
        }
        return result.toString().trim();
    }

    /**
     * Send APDU command, response data of '61xx' is completed with GET RESPONSE like a terminal does.
     */
    static ResponseAPDU send(String apdu) throws CardException {
        ResponseAPDU response = SmartCard.transmitCommand(hex(apdu));
        byte[] data = response.getData();
        while (response.getSW1() == 0x61) {
            response = SmartCard.transmitCommand(hex(String.format("00 C0 00 00 %02X", response.getSW2())));
            data = concat(data, response.getData());
        }
        return new ResponseAPDU(concat(data, new byte[] { (byte) response.getSW1(), (byte) response.getSW2() }));
    }

    /**
     * Offset of the first data object in a response template, after the template tag and its one to three byte length.
     */
    static int templateValueOffset(byte[] template) {
        switch (template[1]) {
            case (byte) 0x81:
                return 3;
            case (byte) 0x82:
                return 4;
            default:
                return 2;
        }
    }

    static void assertSw(int expectedSw, ResponseAPDU response) {
        assertEquals(String.format("%04X", expectedSw), String.format("%04X", response.getSW()));
    }

    /**
     * Find value of a primitive tag from the response template 77.
     */
    static byte[] findTag(byte[] template, int tag) {
        int offset = templateValueOffset(template);
        while (offset < template.length) {
            int tagId = template[offset] & 0xFF;
            offset++;
            if ((tagId & 0x1F) == 0x1F) {
                tagId = (tagId << 8) | (template[offset] & 0xFF);
                offset++;
            }

            int length = template[offset] & 0xFF;
            offset++;
            if (length == 0x81) {
                length = template[offset] & 0xFF;
                offset++;
            }

            if (tagId == tag) {
                return Arrays.copyOfRange(template, offset, offset + length);
            }
            offset += length;
        }
        return null;
    }

    /**
     * Response template 77 data objects excluding Signed Dynamic Application Data, as BER-TLV.
     */
    static byte[] responseTlvsWithoutSdad(byte[] template) {
        byte[] result = new byte[0];
        int offset = templateValueOffset(template);
        while (offset < template.length) {
            int start = offset;
            int tagId = template[offset] & 0xFF;
            offset++;
            if ((tagId & 0x1F) == 0x1F) {
                tagId = (tagId << 8) | (template[offset] & 0xFF);
                offset++;
            }

            int length = template[offset] & 0xFF;
            offset++;
            if (length == 0x81) {
                length = template[offset] & 0xFF;
                offset++;
            }
            offset += length;

            if (tagId != 0x9F4B) {
                result = concat(result, Arrays.copyOfRange(template, start, offset));
            }
        }
        return result;
    }

    /**
     * Start simulator with one applet and personalize it with the setup file, returns the ICC RSA key modulus if the file sets it.
     */
    static BigInteger installAndPersonalize(byte[] aid, Class<? extends Applet> applet, String setupFile) throws CardException, IOException {
        SmartCard.setLogging(false);
        SmartCard.connect();
        SmartCard.install(aid, applet);
        return personalize(setupFile);
    }

    /**
     * Send setup commands of a card setup file, returns the ICC RSA key modulus if the file sets it.
     */
    static BigInteger personalize(String setupFile) throws CardException, IOException {
        BigInteger iccModulus = null;
        List<String> lines = Files.readAllLines(Paths.get(setupFile), StandardCharsets.UTF_8);
        for (String line : lines) {
            String trimmed = line.trim();
            if (!trimmed.startsWith("- req: '")) {
                continue;
            }

            String request = trimmed.substring("- req: '".length(), trimmed.length() - 1);
            if (request.startsWith("80 00 00 04 ")) {
                iccModulus = new BigInteger(1, Arrays.copyOfRange(hex(request), 5, hex(request).length));
            }

            assertSw(0x9000, send(request));
        }
        return iccModulus;
    }

    /**
     * Recover data signed with the ICC private key.
     */
    static byte[] recoverSignedData(BigInteger modulus, byte[] signature) {
        assertEquals(modulus.bitLength() / 8, signature.length);
        byte[] recovered = new BigInteger(1, signature).modPow(ICC_PUBLIC_EXPONENT, modulus).toByteArray();
        return Arrays.copyOfRange(recovered, recovered.length - signature.length, recovered.length);
    }
}
