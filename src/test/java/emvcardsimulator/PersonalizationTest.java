package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.findTag;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.send;
import static emvcardsimulator.EmvTestUtil.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Personalization of the payment application with data groupings of the EMV Card Personalization Specification: records as is,
 * interface specific data, applications with their own data, ICC private key CRT components and PIN Try Limit.
 */
public class PersonalizationTest {
    private static final byte[] APPLET_AID = hex("AF FF FF FF FF 12 34");
    private static final String SELECT = "00 A4 04 00 07 AF FF FF FF FF 12 34 00";

    // Record template with CDOL1 (8C) of Amount, Authorised and Unpredictable Number, and a PAN (5A)
    private static final String RECORD = "70 10 8C 06 9F 02 06 9F 37 04 5A 06 12 34 56 78 90 12";

    /**
     * Install the payment application and start its personalization.
     */
    @BeforeEach
    public void setup() throws CardException {
        SmartCard.setLogging(false);
        SmartCard.connect(SmartCard.PROTOCOL_T1);
        SmartCard.install(APPLET_AID, PaymentApplicationContainer.class);
        personalize(SELECT);
    }

    /**
     * Disconnect card.
     */
    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    private static void personalize(String select) throws CardException {
        assertSw(0x9000, send(select));
        assertSw(0x9000, send("80 05 00 00 00"));
        assertSw(0x9000, send("80 01 00 84 07 AF FF FF FF FF 12 34"));
    }

    /**
     * Record is returned as is and its data objects are card data, e.g. CDOL1 gives the GENERATE AC data length.
     * Default response templates of GENERATE AC and FCI, ATC starts from zero.
     */
    @Test
    public void readRecordDataTest() throws CardException {
        assertSw(ISO7816.SW_DATA_INVALID, send("80 04 01 0C 03 77 01 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 04 01 0C 04 70 03 5A 01"));
        assertSw(0x9000, send("80 04 01 0C 12 " + RECORD));
        assertSw(0x9000, send("80 01 00 A5 00"));
        assertSw(0x9000, send("80 01 00 82 02 18 00"));
        assertSw(0x9000, send("80 01 9F 10 07 06 01 12 03 00 00 00"));
        assertSw(0x9000, send("80 00 00 07 10 01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"));

        ResponseAPDU response = send(SELECT);
        assertSw(0x9000, response);
        assertArrayEquals(hex("6F 0B 84 07 AF FF FF FF FF 12 34 A5 00"), Arrays.copyOf(response.getData(), 13));

        response = send("00 B2 01 0C 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex(RECORD), response.getData());

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertArrayEquals(hex("9F 36 02 00 01"), send("80 CA 9F 36 00").getData());

        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 AE 80 00 09 00 00 00 00 00 01 01 23 45 00"));
        response = send("80 AE 80 00 0A 00 00 00 00 00 01 01 23 45 67 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("80"), findTag(response.getData(), 0x9F27));
        assertArrayEquals(hex("00 01"), findTag(response.getData(), 0x9F36));
        assertEquals(8, findTag(response.getData(), 0x9F26).length);
        // Card Verification Results are not updated without the CVR setting
        assertArrayEquals(hex("06 01 12 03 00 00 00"), findTag(response.getData(), 0x9F10));
    }

    /**
     * Contactless FCI and GET PROCESSING OPTIONS response take precedence on the contactless interface, data objects of the
     * contactless FCI Proprietary Template (PDOL) are only on the contactless interface.
     */
    @Test
    public void interfaceScopeTest() throws CardException {
        assertSw(0x9000, send("80 04 01 0C 12 " + RECORD));
        assertSw(0x9000, send("80 01 00 A5 03 50 01 41"));
        assertSw(0x9000, send("80 01 00 82 02 18 00"));
        assertSw(0x9000, send("80 01 00 94 04 08 01 01 00"));
        assertSw(0x9000, send("80 02 00 01 04 00 82 00 94"));

        assertSw(ISO7816.SW_DATA_INVALID, send("80 00 00 12 01 03"));
        assertSw(0x9000, send("80 00 00 12 01 02"));
        assertSw(0x9000, send("80 01 00 A5 09 50 01 43 9F 38 03 9F 37 04"));
        assertSw(0x9000, send("80 01 00 82 02 00 20"));
        // Only GET PROCESSING OPTIONS response template has an interface specific variant
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 02 00 03 02 9F 27"));
        assertSw(0x9000, send("80 02 00 01 02 00 82"));
        assertSw(0x9000, send("80 00 00 12 01 00"));

        ResponseAPDU response = send(SELECT);
        assertArrayEquals(hex("50 01 41"), findTag(response.getData(), 0xA5));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 A8 00 00 04 83 02 00 00 00"));
        assertArrayEquals(hex("77 0A 82 02 18 00 94 04 08 01 01 00 90 00"), send("80 A8 00 00 02 83 00 00").getBytes());

        SmartCard.changeProtocol(SmartCard.PROTOCOL_CONTACTLESS);
        response = send(SELECT);
        assertArrayEquals(hex("50 01 43 9F 38 03 9F 37 04"), findTag(response.getData(), 0xA5));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 A8 00 00 02 83 00 00"));
        assertArrayEquals(hex("77 04 82 02 00 20 90 00"), send("80 A8 00 00 06 83 04 12 34 56 78 00").getBytes());

        // Record data is on both interfaces
        assertArrayEquals(hex(RECORD + " 90 00"), send("00 B2 01 0C 00").getBytes());
    }

    /**
     * Applications of a card have their own data.
     */
    @Test
    public void applicationDataTest() throws CardException {
        assertSw(0x9000, send("80 04 01 0C 12 " + RECORD));
        assertSw(0x9000, send("80 01 00 A5 03 50 01 41"));

        SmartCard.install(hex("AF FF FF FF FF 12 35"), PaymentApplicationContainer.class);
        personalize("00 A4 04 00 07 AF FF FF FF FF 12 35 00");
        assertSw(0x9000, send("80 01 00 84 07 AF FF FF FF FF 12 35"));
        assertSw(0x9000, send("80 04 01 0C 05 70 03 5A 01 99"));
        assertSw(0x9000, send("80 01 00 A5 03 50 01 42"));

        ResponseAPDU response = send(SELECT);
        assertArrayEquals(hex("50 01 41"), findTag(response.getData(), 0xA5));
        assertArrayEquals(hex(RECORD + " 90 00"), send("00 B2 01 0C 00").getBytes());

        response = send("00 A4 04 00 07 AF FF FF FF FF 12 35 00");
        assertArrayEquals(hex("50 01 42"), findTag(response.getData(), 0xA5));
        assertArrayEquals(hex("70 03 5A 01 99 90 00"), send("00 B2 01 0C 00").getBytes());
    }

    private static String component(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[length];
        int copyLength = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - copyLength, result, length - copyLength, copyLength);
        return String.format("%02X ", length) + toHex(result);
    }

    /**
     * ICC private key from the Chinese Remainder Theorem components, DDA signature is verified with the public key.
     */
    @Test
    public void rsaCrtKeyTest() throws CardException, GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(1024, EmvTestUtil.ICC_PUBLIC_EXPONENT));
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) generator.generateKeyPair().getPrivate();

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 00 00 14 40 " + component(key.getPrimeQ(), 64).substring(3)));
        assertSw(0x9000, send("80 00 00 13 " + component(key.getPrimeP(), 64)));
        assertSw(0x9000, send("80 00 00 14 " + component(key.getPrimeQ(), 64)));
        assertSw(0x9000, send("80 00 00 15 " + component(key.getPrimeExponentP(), 64)));
        assertSw(0x9000, send("80 00 00 16 " + component(key.getPrimeExponentQ(), 64)));
        assertSw(0x9000, send("80 00 00 17 " + component(key.getCrtCoefficient(), 64)));
        // Modulus and private exponent key setting does not apply to a CRT key
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 00 00 05 01 03"));

        ResponseAPDU response = send("00 88 00 00 04 01 02 03 04 00");
        assertSw(0x9000, response);
        byte[] recovered = EmvTestUtil.recoverSignedData(key.getModulus(), findTag(response.getData(), 0x9F4B));
        assertArrayEquals(hex("6A 05 01"), Arrays.copyOf(recovered, 3));
        assertEquals((byte) 0xBC, recovered[recovered.length - 1]);
    }

    /**
     * PIN Try Counter is reset to the PIN Try Limit.
     */
    @Test
    public void pinTryLimitTest() throws CardException {
        assertSw(ISO7816.SW_DATA_INVALID, send("80 00 00 18 01 10"));
        assertSw(0x9000, send("80 00 00 18 01 05"));
        assertSw(0x9000, send("80 00 00 01 02 12 34"));
        assertArrayEquals(hex("9F 17 01 05"), send("80 CA 9F 17 00").getData());

        assertSw(0x63C4, send("00 20 00 80 08 24 99 99 FF FF FF FF FF"));
        assertSw(0x9000, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));
        assertArrayEquals(hex("9F 17 01 05"), send("80 CA 9F 17 00").getData());
    }
}
