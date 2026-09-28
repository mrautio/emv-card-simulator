package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.concat;
import static emvcardsimulator.EmvTestUtil.deriveSessionKey;
import static emvcardsimulator.EmvTestUtil.des;
import static emvcardsimulator.EmvTestUtil.findTag;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.retailMac;
import static emvcardsimulator.EmvTestUtil.send;
import static emvcardsimulator.EmvTestUtil.sha1;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.crypto.Cipher;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Contactless transactions of the payment application: qVSDC with fDDA, mag-stripe mode CVC3 and torn transaction recovery.
 */
public class ContactlessTransactionTest {
    private static final byte[] APPLET_AID = hex("AF FF FF FF FF 12 34");
    private static final String SETUP_FILE = "../config/card_setup_app_apdus.yaml";
    private static final String SELECT = "00 A4 04 00 07 AF FF FF FF FF 12 34 00";

    // CDOL1 of the test profile: 9F02 06, 9F03 06, 9F1A 02, 95 05, 5F2A 02, 9A 03, 9C 01, 9F37 04
    private static final String CDOL1_DATA = "000000000001 000000000000 0246 0000000000 0978 200724 21 01234567";
    // PDOL: Terminal Transaction Qualifiers followed by the CDOL1 data objects
    private static final String PDOL = "9F 66 04 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04";
    private static final String AC_MASTER_KEY = "0123456789ABCDEF FEDCBA9876543210";
    private static final String AIP = "3C00";
    private static final String CVC3_KEY = "00112233445566778899AABBCCDDEEFF";

    // Terminal Transaction Qualifiers: qVSDC supported, online cryptogram required
    private static final String TTQ_ONLINE_CRYPTOGRAM_REQUIRED = "36 80 00 00";
    // Offline-only reader
    private static final String TTQ_OFFLINE_ONLY = "28 00 00 00";
    // Online capable reader, online cryptogram not required
    private static final String TTQ_ONLINE_CAPABLE = "26 00 00 00";

    private BigInteger iccModulus;

    @BeforeEach
    public void setup() throws CardException, IOException {
        iccModulus = EmvTestUtil.installAndPersonalize(APPLET_AID, PaymentApplicationContainer.class, SETUP_FILE);
        assertSw(0x9000, send(SELECT));
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    private static byte[] applicationCryptogram(byte[] atc, byte[]... data) throws GeneralSecurityException {
        return retailMac(deriveSessionKey(hex(AC_MASTER_KEY), atc), concat(data));
    }

    /**
     * Personalize qVSDC: cryptogram in GET PROCESSING OPTIONS, PDOL and GET PROCESSING OPTIONS response template.
     */
    private static void enableQvsdc(String flags, String responseTags) throws CardException {
        assertSw(0x9000, send("80 00 00 03 02 " + flags));
        assertSw(0x9000, send("80 01 9F 38 18 " + PDOL));
        assertSw(0x9000, send("80 01 9F 6C 02 80 00"));
        assertSw(0x9000, send(String.format("80 02 00 01 %02X %s", hex(responseTags).length, responseTags)));
    }

    private static ResponseAPDU qvsdcTransaction(String terminalTransactionQualifiers) throws CardException {
        assertSw(0x9000, send(SELECT));
        ResponseAPDU response = send("80 A8 00 00 23 83 21 " + terminalTransactionQualifiers + " " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        return response;
    }

    private static byte cryptogramType(ResponseAPDU response) {
        return findTag(response.getData(), 0x9F27)[0];
    }

    @Test
    public void qvsdcOnlineTest() throws CardException, GeneralSecurityException {
        enableQvsdc("00 05", "82 94 57 9F 10 9F 26 9F 27 9F 36 9F 6C");

        ResponseAPDU response = qvsdcTransaction(TTQ_ONLINE_CRYPTOGRAM_REQUIRED);
        assertEquals((byte) 0x80, cryptogramType(response));
        assertArrayEquals(hex("00 F1"), findTag(response.getData(), 0x9F36));
        assertArrayEquals(hex("80 00"), findTag(response.getData(), 0x9F6C));

        // Application Cryptogram over PDOL related data arranged as CDOL1 related data
        assertArrayEquals(applicationCryptogram(hex("00 F1"), hex(CDOL1_DATA), hex(AIP), hex("00 F1")), findTag(response.getData(), 0x9F26));

        // Transaction is completed in GET PROCESSING OPTIONS
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 80 00 1D " + CDOL1_DATA + " 00"));
    }

    @Test
    public void qvsdcOfflineOnlyReaderTest() throws CardException, GeneralSecurityException {
        enableQvsdc("00 05", "82 94 57 9F 10 9F 26 9F 27 9F 36");

        ResponseAPDU response = qvsdcTransaction(TTQ_OFFLINE_ONLY);
        assertEquals((byte) 0x40, cryptogramType(response));
        assertArrayEquals(applicationCryptogram(hex("00 F1"), hex(CDOL1_DATA), hex(AIP), hex("00 F1")), findTag(response.getData(), 0x9F26));

        // Without card risk management, card goes online with online capable reader
        assertEquals((byte) 0x80, cryptogramType(qvsdcTransaction(TTQ_ONLINE_CAPABLE)));
    }

    @Test
    public void qvsdcCardRiskManagementTest() throws CardException {
        // Card risk management enabled, Lower Consecutive Offline Limit 1, Upper Consecutive Offline Limit 2
        enableQvsdc("00 0D", "82 94 57 9F 10 9F 26 9F 27 9F 36");
        assertSw(0x9000, send("80 01 9F 14 01 01"));
        assertSw(0x9000, send("80 01 9F 23 01 02"));

        assertEquals((byte) 0x40, cryptogramType(qvsdcTransaction(TTQ_ONLINE_CAPABLE)));
        assertEquals((byte) 0x80, cryptogramType(qvsdcTransaction(TTQ_ONLINE_CAPABLE)));
        assertEquals((byte) 0x80, cryptogramType(qvsdcTransaction(TTQ_ONLINE_CRYPTOGRAM_REQUIRED)));

        // Offline-only reader: approved until the upper limit, then declined
        assertEquals((byte) 0x40, cryptogramType(qvsdcTransaction(TTQ_OFFLINE_ONLY)));
        assertEquals((byte) 0x00, cryptogramType(qvsdcTransaction(TTQ_OFFLINE_ONLY)));
    }

    @Test
    public void fastDynamicDataAuthenticationTest() throws CardException, GeneralSecurityException {
        // Random disabled, Card Unpredictable Number is 'AB AB AB AB'
        enableQvsdc("00 04", "82 94 57 9F 10 9F 26 9F 27 9F 36 9F 4B 9F 69 9F 6C");

        ResponseAPDU response = qvsdcTransaction(TTQ_ONLINE_CRYPTOGRAM_REQUIRED);
        byte[] cardAuthenticationRelatedData = findTag(response.getData(), 0x9F69);
        assertArrayEquals(hex("01 AB AB AB AB 80 00"), cardAuthenticationRelatedData);

        byte[] recovered = EmvTestUtil.recoverSignedData(iccModulus, findTag(response.getData(), 0x9F4B));
        int length = recovered.length;
        assertArrayEquals(hex("6A 05 01 04 03"), Arrays.copyOfRange(recovered, 0, 5));
        assertEquals((byte) 0xBC, recovered[length - 1]);

        // Terminal dynamic data: Unpredictable Number, Amount, Authorised, Transaction Currency Code, Card Authentication Related Data
        byte[] hash = sha1(Arrays.copyOfRange(recovered, 1, length - 21), hex("01 23 45 67 000000000001 0978"), cardAuthenticationRelatedData);
        assertArrayEquals(hash, Arrays.copyOfRange(recovered, length - 21, length - 1));
    }

    private static byte[] cvc3(String initializationVector, String unpredictableNumber, String atc) throws GeneralSecurityException {
        byte[] result = des(Cipher.ENCRYPT_MODE, hex(CVC3_KEY), hex(initializationVector + unpredictableNumber + atc));
        return Arrays.copyOfRange(result, 6, 8);
    }

    @Test
    public void computeCryptographicChecksumTest() throws CardException, GeneralSecurityException {
        // Not supported without KD_CVC3
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("80 2A 8E 80 04 00 00 12 34 00"));

        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 0C 02 11 22"));
        assertSw(0x9000, send("80 00 00 0B 10 " + CVC3_KEY));
        assertSw(0x9000, send("80 00 00 0C 04 11 22 33 44"));

        assertSw(0x9000, send(SELECT));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 2A 8E 80 04 00 00 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 2A 8E 00 04 00 00 12 34 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 2A 8E 80 03 00 12 34 00"));

        // Default UDOL is Unpredictable Number (Numeric), ATC is 00 F2 after the second GET PROCESSING OPTIONS
        ResponseAPDU response = send("80 2A 8E 80 04 00 00 12 34 00");
        assertSw(0x9000, response);
        byte[] expected = concat(hex("77 0F 9F 61 02"), cvc3("33 44", "00 00 12 34", "00 F2"),
            hex("9F 60 02"), cvc3("11 22", "00 00 12 34", "00 F2"), hex("9F 36 02 00 F2"));
        assertArrayEquals(expected, response.getData());

        // Only once per transaction
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 2A 8E 80 04 00 00 12 34 00"));
    }

    @Test
    public void computeCryptographicChecksumWithUdolTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 00 00 0B 10 " + CVC3_KEY));
        assertSw(0x9000, send("80 00 00 0C 04 11 22 33 44"));
        // UDOL: Amount, Authorised and Unpredictable Number (Numeric)
        assertSw(0x9000, send("80 01 9F 69 06 9F 02 06 9F 6A 04"));
        // Response template: CVC3 Track2 and ATC
        assertSw(0x9000, send("80 02 00 07 04 9F 61 9F 36"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 2A 8E 80 04 00 00 56 78 00"));

        ResponseAPDU response = send("80 2A 8E 80 0A 00 00 00 00 00 01 00 00 56 78 00");
        assertSw(0x9000, response);
        assertArrayEquals(concat(hex("77 0A 9F 61 02"), cvc3("33 44", "00 00 56 78", "00 F1"), hex("9F 36 02 00 F1")), response.getData());
    }

    @Test
    public void recoverAcTest() throws CardException {
        // Not supported without DRDOL
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("80 D0 00 00 0A 01 23 45 67 00 00 00 00 00 01 00"));

        // DRDOL: Unpredictable Number, Amount, Authorised
        assertSw(0x9000, send("80 01 9F 51 06 9F 37 04 9F 02 06"));

        // Torn transaction: terminal did not receive the GENERATE AC response
        assertSw(0x9000, send(SELECT));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        ResponseAPDU tornResponse = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, tornResponse);

        assertSw(0x9000, send(SELECT));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 D0 00 00 0A 01 23 45 67 00 00 00 00 00 01 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 D0 00 01 0A 01 23 45 67 00 00 00 00 00 01 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 D0 00 00 09 01 23 45 67 00 00 00 00 01 00"));
        // DRDOL related data of another transaction
        assertSw(0x6A88, send("80 D0 00 00 0A 01 23 45 68 00 00 00 00 00 01 00"));

        ResponseAPDU response = send("80 D0 00 00 0A 01 23 45 67 00 00 00 00 00 01 00");
        assertSw(0x9000, response);
        assertArrayEquals(tornResponse.getData(), response.getData());

        // RECOVER AC completes the transaction
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 80 00 1D " + CDOL1_DATA + " 00"));
    }

    @Test
    public void recoverAcNotMatchingTest() throws CardException {
        assertSw(0x9000, send("80 01 9F 51 06 9F 37 04 9F 02 06"));

        // No torn transaction
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(0x6A88, send("80 D0 00 00 0A 01 23 45 67 00 00 00 00 00 01 00"));

        // Transaction continues with GENERATE AC
        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertEquals((byte) 0x80, findTag(response.getData(), 0x9F27)[0]);
    }
}
