package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * EMV protocol behaviour of the payment application with the test card profile.
 */
public class PaymentApplicationProtocolTest {
    private static final byte[] APPLET_AID = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 };
    private static final String SETUP_FILE = "../config/card_setup_app_apdus.yaml";

    private static final BigInteger ICC_PUBLIC_EXPONENT = BigInteger.valueOf(3);

    // CDOL1 of the test profile: 9F02 06, 9F03 06, 9F1A 02, 95 05, 5F2A 02, 9A 03, 9C 01, 9F37 04
    private static final String CDOL1_DATA = "000000000001 000000000000 0246 0000000000 0978 200724 21 01234567";
    // CDOL2 of the test profile: 8A 02 followed by CDOL1 data objects
    private static final String CDOL2_DATA = "5933 " + CDOL1_DATA;
    private static final byte[] APPLICATION_CRYPTOGRAM = hex("B0189101D11416C1");

    private BigInteger iccModulus;

    private static byte[] hex(String data) {
        String compact = data.replace(" ", "");
        byte[] result = new byte[compact.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(compact.substring(i * 2, i * 2 + 2), 16);
        }
        return result;
    }

    private static byte[] concat(byte[]... arrays) {
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

    private static byte[] sha1(byte[]... arrays) throws NoSuchAlgorithmException {
        return MessageDigest.getInstance("SHA-1").digest(concat(arrays));
    }

    private static ResponseAPDU send(String apdu) throws CardException {
        return SmartCard.transmitCommand(hex(apdu));
    }

    private static void assertSw(int expectedSw, ResponseAPDU response) {
        assertEquals(String.format("%04X", expectedSw), String.format("%04X", response.getSW()));
    }

    /**
     * Find value of a primitive tag from the response template 77.
     */
    private static byte[] findTag(byte[] template, int tag) {
        int offset = (template[1] == (byte) 0x81) ? 3 : 2;
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
    private static byte[] responseTlvsWithoutSdad(byte[] template) {
        byte[] result = new byte[0];
        int offset = (template[1] == (byte) 0x81) ? 3 : 2;
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

    private byte[] recoverSignedData(byte[] signature) {
        assertEquals(iccModulus.bitLength() / 8, signature.length);
        byte[] recovered = new BigInteger(1, signature).modPow(ICC_PUBLIC_EXPONENT, iccModulus).toByteArray();
        return Arrays.copyOfRange(recovered, recovered.length - signature.length, recovered.length);
    }

    private byte[] encipherPin(byte[] pinBlock, byte[] challenge) {
        int keySize = iccModulus.bitLength() / 8;
        byte[] padding = new byte[keySize - 17];
        Arrays.fill(padding, (byte) 0x55);

        byte[] plaintext = concat(new byte[] { (byte) 0x7F }, pinBlock, challenge, padding);
        byte[] ciphertext = new BigInteger(1, plaintext).modPow(ICC_PUBLIC_EXPONENT, iccModulus).toByteArray();

        byte[] result = new byte[keySize];
        int length = Math.min(ciphertext.length, keySize);
        System.arraycopy(ciphertext, ciphertext.length - length, result, keySize - length, length);
        return result;
    }

    /**
     * Personalize the card with the test profile and select the application.
     */
    @BeforeEach
    public void setup() throws CardException, IOException {
        SmartCard.setLogging(false);
        SmartCard.connect();
        SmartCard.install(APPLET_AID, PaymentApplicationContainer.class);

        List<String> lines = Files.readAllLines(Paths.get(SETUP_FILE), StandardCharsets.UTF_8);
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

        ResponseAPDU response = send("00 A4 04 00 07 AF FF FF FF FF 12 34 00");
        assertSw(0x9000, response);
        assertEquals((byte) 0x6F, response.getData()[0]);
    }

    /**
     * Disconnect card.
     */
    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    @Test
    public void unsupportedClassTest() throws CardException {
        assertSw(ISO7816.SW_CLA_NOT_SUPPORTED, send("A0 B2 01 14 00"));
        assertSw(ISO7816.SW_CLA_NOT_SUPPORTED, send("E0 00 00 01 02 12 34"));
        assertSw(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED, send("84 1E 00 00 08 01 02 03 04 05 06 07 08"));
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("00 CA 9F 36 00"));
    }

    @Test
    public void getDataTest() throws CardException {
        ResponseAPDU response = send("80 CA 9F 36 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("9F 36 02 00 F0"), response.getData());

        assertSw(0x9000, send("80 CA 9F 36 05"));
        assertSw(0x6C05, send("80 CA 9F 36 02"));

        response = send("80 CA 9F 17 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("9F 17 01 03"), response.getData());

        // Only ATC, Last Online ATC Register, PIN Try Counter and Log Format are retrievable
        assertSw(0x6A88, send("80 CA 00 5A 00"));
        assertSw(0x6A88, send("80 CA 9F 13 00"));
    }

    @Test
    public void readRecordExpectedLengthTest() throws CardException {
        ResponseAPDU response = send("00 B2 01 14 00");
        assertSw(0x9000, response);

        int length = response.getData().length;
        assertSw(0x9000, send(String.format("00 B2 01 14 %02X", length)));
        assertSw(0x6C00 | length, send(String.format("00 B2 01 14 %02X", length - 3)));

        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("00 B2 05 14 00"));
    }

    @Test
    public void getProcessingOptionsTest() throws CardException {
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 A8 00 00 03 83 01 00 00"));
        assertSw(ISO7816.SW_DATA_INVALID, send("80 A8 00 00 02 84 00 00"));

        ResponseAPDU response = send("80 A8 00 00 02 83 00 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("77 12 82 02 3C 00 94 0C"), Arrays.copyOfRange(response.getData(), 0, 8));

        // ATC is incremented once per transaction, in GET PROCESSING OPTIONS
        assertArrayEquals(hex("9F 36 02 00 F1"), send("80 CA 9F 36 00").getData());

        // Only one GET PROCESSING OPTIONS per transaction
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 A8 00 00 02 83 00 00"));
    }

    @Test
    public void getProcessingOptionsWithPdolTest() throws CardException {
        // PDOL: Terminal Country Code, Unpredictable Number
        assertSw(0x9000, send("80 01 9F 38 06 9F 1A 02 9F 37 04"));

        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 A8 00 00 07 83 05 02 46 01 23 45 00"));
        assertSw(0x9000, send("80 A8 00 00 08 83 06 02 46 01 23 45 67 00"));
    }

    @Test
    public void applicationTransactionCounterLimitTest() throws CardException {
        assertSw(0x9000, send("80 01 9F 36 02 FF FF"));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 A8 00 00 02 83 00 00"));
    }

    @Test
    public void transactionFlowTest() throws CardException {
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 80 00 1D " + CDOL1_DATA + " 00"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("00 82 00 00 08 12 34 56 78 12 34 56 78"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 AE 80 00 1C " + CDOL1_DATA.replace(" 01234567", " 012345") + " 00"));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 AE C0 00 1D " + CDOL1_DATA + " 00"));

        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("80"), findTag(response.getData(), 0x9F27));
        assertArrayEquals(hex("00 F1"), findTag(response.getData(), 0x9F36));

        assertSw(ISO7816.SW_WRONG_LENGTH, send("00 82 00 00 07 12 34 56 78 12 34 56"));
        assertSw(0x9000, send("00 82 00 00 08 12 34 56 78 12 34 56 78"));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("00 82 00 00 08 12 34 56 78 12 34 56 78"));

        // Second GENERATE AC completes the transaction
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 AE 80 00 1F " + CDOL2_DATA + " 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 AE 40 00 1D " + CDOL1_DATA + " 00"));

        response = send("80 AE 40 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("40"), findTag(response.getData(), 0x9F27));
        // ATC does not change within the transaction
        assertArrayEquals(hex("00 F1"), findTag(response.getData(), 0x9F36));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 40 00 1F " + CDOL2_DATA + " 00"));

        // New transaction after selection
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertArrayEquals(hex("9F 36 02 00 F2"), send("80 CA 9F 36 00").getData());
    }

    @Test
    public void plaintextPinTest() throws CardException {
        assertSw(0x9000, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));

        assertSw(0x63C2, send("00 20 00 80 08 24 12 35 FF FF FF FF FF"));
        // PIN block control field and filler are part of the comparison
        assertSw(0x63C1, send("00 20 00 80 08 25 12 34 FF FF FF FF FF"));
        assertArrayEquals(hex("9F 17 01 01"), send("80 CA 9F 17 00").getData());

        // Successful verification resets PIN Try Counter
        assertSw(0x9000, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));
        assertArrayEquals(hex("9F 17 01 03"), send("80 CA 9F 17 00").getData());

        assertSw(ISO7816.SW_WRONG_LENGTH, send("00 20 00 80 07 24 12 34 FF FF FF FF"));

        assertSw(0x63C2, send("00 20 00 80 08 24 12 34 FF FF FF FF F0"));
        assertSw(0x63C1, send("00 20 00 80 08 24 00 00 FF FF FF FF FF"));
        assertSw(0x6983, send("00 20 00 80 08 24 00 00 FF FF FF FF FF"));

        // PIN is blocked
        assertSw(0x6983, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));
        assertArrayEquals(hex("9F 17 01 00"), send("80 CA 9F 17 00").getData());
    }

    @Test
    public void longPinTest() throws CardException {
        assertSw(0x9000, send("80 00 00 01 03 12 34 5F"));
        assertSw(0x9000, send("00 20 00 80 08 25 12 34 5F FF FF FF FF"));

        assertSw(ISO7816.SW_DATA_INVALID, send("80 00 00 01 02 12 3F"));
        assertSw(ISO7816.SW_DATA_INVALID, send("80 00 00 01 03 12 F4 FF"));
    }

    @Test
    public void encipheredPinTest() throws CardException {
        byte[] pinBlock = hex("24 12 34 FF FF FF FF FF");

        // ICC Unpredictable Number is required
        byte[] enciphered = encipherPin(pinBlock, new byte[8]);
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(concat(hex("00 20 00 88 80"), enciphered)));

        assertSw(0x6C08, send("00 84 00 00 04"));

        ResponseAPDU response = send("00 84 00 00 00");
        assertSw(0x9000, response);
        assertEquals(8, response.getData().length);

        enciphered = encipherPin(pinBlock, response.getData());
        assertSw(ISO7816.SW_WRONG_LENGTH, SmartCard.transmitCommand(concat(hex("00 20 00 88 7F"), Arrays.copyOf(enciphered, 0x7F))));
        assertSw(0x9000, SmartCard.transmitCommand(concat(hex("00 20 00 88 80"), enciphered)));

        // ICC Unpredictable Number is single use
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(concat(hex("00 20 00 88 80"), enciphered)));

        response = send("00 84 00 00 00");
        enciphered = encipherPin(hex("24 43 21 FF FF FF FF FF"), response.getData());
        assertSw(0x63C2, SmartCard.transmitCommand(concat(hex("00 20 00 88 80"), enciphered)));
    }

    @Test
    public void dynamicDataAuthenticationTest() throws CardException, NoSuchAlgorithmException {
        // DDOL of the test profile: 9F37 04
        assertSw(ISO7816.SW_WRONG_LENGTH, send("00 88 00 00 03 01 23 45 00"));

        ResponseAPDU response = send("00 88 00 00 04 01 23 45 67 00");
        assertSw(0x9000, response);

        byte[] recovered = recoverSignedData(findTag(response.getData(), 0x9F4B));
        int length = recovered.length;
        assertArrayEquals(hex("6A 05 01"), Arrays.copyOfRange(recovered, 0, 3));
        assertEquals((byte) 0xBC, recovered[length - 1]);

        // ICC Dynamic Data: length of ICC Dynamic Number followed by ICC Dynamic Number
        assertEquals(4, recovered[3]);
        assertEquals(3, recovered[4]);

        byte[] hash = sha1(Arrays.copyOfRange(recovered, 1, length - 21), hex("01 23 45 67"));
        assertArrayEquals(hash, Arrays.copyOfRange(recovered, length - 21, length - 1));
    }

    private void assertCombinedDataAuthentication(byte[] template, byte cryptogramType, byte[] transactionData) throws NoSuchAlgorithmException {
        // Application Cryptogram is inside the signature
        assertEquals(null, findTag(template, 0x9F26));
        assertArrayEquals(new byte[] { cryptogramType }, findTag(template, 0x9F27));

        byte[] recovered = recoverSignedData(findTag(template, 0x9F4B));
        int length = recovered.length;
        assertArrayEquals(hex("6A 05 01"), Arrays.copyOfRange(recovered, 0, 3));
        assertEquals((byte) 0xBC, recovered[length - 1]);

        // ICC Dynamic Data
        assertEquals(1 + 3 + 1 + 8 + 20, recovered[3]);
        assertEquals(3, recovered[4]);
        assertEquals(cryptogramType, recovered[8]);
        assertArrayEquals(APPLICATION_CRYPTOGRAM, Arrays.copyOfRange(recovered, 9, 17));

        byte[] transactionDataHashCode = sha1(transactionData, responseTlvsWithoutSdad(template));
        assertArrayEquals(transactionDataHashCode, Arrays.copyOfRange(recovered, 17, 37));

        byte[] hash = sha1(Arrays.copyOfRange(recovered, 1, length - 21), hex("01 23 45 67"));
        assertArrayEquals(hash, Arrays.copyOfRange(recovered, length - 21, length - 1));
    }

    @Test
    public void combinedDataAuthenticationTest() throws CardException, NoSuchAlgorithmException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x80, hex(CDOL1_DATA));

        response = send("80 AE 50 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x40, concat(hex(CDOL1_DATA), hex(CDOL2_DATA)));
    }

    @Test
    public void combinedDataAuthenticationWithPdolTest() throws CardException, NoSuchAlgorithmException {
        assertSw(0x9000, send("80 01 9F 38 06 9F 1A 02 9F 37 04"));
        assertSw(0x9000, send("80 A8 00 00 08 83 06 02 46 01 23 45 67 00"));

        ResponseAPDU response = send("80 AE 50 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x40, concat(hex("02 46 01 23 45 67"), hex(CDOL1_DATA)));
    }

    @Test
    public void combinedDataAuthenticationNotForAacTest() throws CardException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 10 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("00"), findTag(response.getData(), 0x9F27));
        assertArrayEquals(APPLICATION_CRYPTOGRAM, findTag(response.getData(), 0x9F26));
        assertTrue(findTag(response.getData(), 0x9F4B) == null);
    }

    @Test
    public void apduLogTest() throws CardException {
        // Clear log
        assertSw(0x9000, send("80 06 01 00 00"));

        // Setup commands are interleaved with EMV commands, but only EMV commands and responses are logged
        assertSw(0x9000, send("80 01 9F 36 02 00 F5"));
        assertSw(0x9000, send("80 00 00 02 02 00 80"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(0x9000, send("80 11 9F 36 04 00 00 00 00"));
        assertSw(0x9000, send("80 CA 9F 36 00"));

        String[] expectedLog = new String[] {
            "80 A8 00 00 02 83 00",
            // Format 1 response starts with 80 like the setup commands
            "80 0E 3C 00 08 02 02 00 10 01 02 00 18 01 02 01",
            "80 CA 9F 36 00",
            "9F 36 02 00 F6",
        };

        for (String expected : expectedLog) {
            ResponseAPDU response = send("80 06 00 00 00");
            assertSw(0x9000, response);
            assertArrayEquals(hex(expected), response.getData());
        }

        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("80 06 00 00 00"));
    }
}
