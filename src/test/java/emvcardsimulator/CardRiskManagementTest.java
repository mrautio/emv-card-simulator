package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.concat;
import static emvcardsimulator.EmvTestUtil.deriveSessionKey;
import static emvcardsimulator.EmvTestUtil.des;
import static emvcardsimulator.EmvTestUtil.findTag;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.macAlgorithm3;
import static emvcardsimulator.EmvTestUtil.send;
import static emvcardsimulator.EmvTestUtil.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.crypto.Cipher;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Card risk management, Card Verification Results, transaction log, PIN encipherment key, data objects and PUT DATA
 * of the payment application with the test card profile, on the contact interface with T=1.
 */
public class CardRiskManagementTest {
    private static final byte[] APPLET_AID = hex("AF FF FF FF FF 12 34");
    private static final String SETUP_FILE = "../config/card_setup_app_apdus.yaml";
    private static final String SELECT = "00 A4 04 00 07 AF FF FF FF FF 12 34 00";

    // CDOL1 of the test profile: 9F02 06, 9F03 06, 9F1A 02, 95 05, 5F2A 02, 9A 03, 9C 01, 9F37 04. Amount, Authorised is 0.01
    private static final String CDOL1_DATA = "000000000001 000000000000 0246 0000000000 0978 200724 21 01234567";
    // Authorisation Response Codes: approved online, and unable to go online (offline approved)
    private static final String ARC_APPROVED = "3030";
    private static final String ARC_UNABLE_TO_GO_ONLINE = "5933";
    private static final String AC_MASTER_KEY = "0123456789ABCDEF FEDCBA9876543210";
    private static final String SM_MAC_MASTER_KEY = "89ABCDEF01234567 76543210FEDCBA98";

    // Flags: random enabled, Issuer Application Data in Application Cryptogram and card risk management enabled
    private static final String CARD_RISK_MANAGEMENT_ENABLED = "80 00 00 03 02 00 0B";

    private BigInteger iccModulus;

    private byte[] secureMessagingSessionKey;
    private byte[] secureMessagingMacChain;

    /**
     * Transport protocol of the tests.
     */
    protected String protocol() {
        return SmartCard.PROTOCOL_T1;
    }

    @BeforeEach
    public void setup() throws CardException, IOException {
        iccModulus = EmvTestUtil.installAndPersonalize(protocol(), APPLET_AID, PaymentApplicationContainer.class, SETUP_FILE);
        assertSw(0x9000, send(SELECT));
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    /**
     * Start a new transaction: SELECT and GET PROCESSING OPTIONS.
     */
    private static void startTransaction() throws CardException {
        assertSw(0x9000, send(SELECT));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
    }

    private static ResponseAPDU firstGenerateAc(String referenceControlParameter) throws CardException {
        ResponseAPDU response = send("80 AE " + referenceControlParameter + " 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        return response;
    }

    private static ResponseAPDU secondGenerateAc(String authorisationResponseCode) throws CardException {
        ResponseAPDU response = send("80 AE 40 00 1F " + authorisationResponseCode + " " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        return response;
    }

    private static byte cryptogramType(ResponseAPDU response) {
        return findTag(response.getData(), 0x9F27)[0];
    }

    /**
     * Transaction where the terminal requests offline approval, returns the Cryptogram Information Data of the first GENERATE AC.
     */
    private static byte offlineTransaction() throws CardException {
        startTransaction();
        return cryptogramType(firstGenerateAc("40"));
    }

    /**
     * Online authorisation approved by the issuer with ARPC Method 1 in EXTERNAL AUTHENTICATE.
     */
    private static ResponseAPDU approveOnline(ResponseAPDU arqcResponse) throws CardException, GeneralSecurityException {
        byte[] atc = findTag(arqcResponse.getData(), 0x9F36);
        byte[] arpc = Arrays.copyOf(findTag(arqcResponse.getData(), 0x9F26), 8);
        arpc[0] ^= hex(ARC_APPROVED)[0];
        arpc[1] ^= hex(ARC_APPROVED)[1];
        arpc = des(Cipher.ENCRYPT_MODE, deriveSessionKey(hex(AC_MASTER_KEY), atc), arpc);

        assertSw(0x9000, send("00 82 00 00 0A " + toHex(arpc) + " " + ARC_APPROVED));
        return secondGenerateAc(ARC_APPROVED);
    }

    /**
     * Issuer script command without data with secure messaging, chained from the first Application Cryptogram.
     */
    private String scriptCommand(String header) throws GeneralSecurityException {
        byte[] mac = macAlgorithm3(secureMessagingSessionKey, concat(secureMessagingMacChain, hex(header), hex("80 00 00 00")));
        secureMessagingMacChain = mac;
        return header + " 0A 8E 08 " + toHex(mac);
    }

    @Test
    public void visaCardVerificationResultsTest() throws CardException, GeneralSecurityException {
        // Visa CVR '03' || 3 bytes at offset 3 of the Issuer Application Data '06 01 12 03 A4 A0 02'
        assertSw(0x9000, send("80 00 00 0D 02 02 03"));
        startTransaction();

        assertSw(0x63C2, send("00 20 00 80 08 24 12 35 FF FF FF FF FF"));
        assertSw(0x9000, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));

        // Second GENERATE AC not requested, ARQC, offline PIN performed and failed. New card (no Last Online ATC Register)
        ResponseAPDU response = firstGenerateAc("80");
        assertArrayEquals(hex("06 01 12 03 A6 10 00"), findTag(response.getData(), 0x9F10));

        // TC in second GENERATE AC after successful issuer authentication
        response = approveOnline(response);
        assertEquals((byte) 0x40, cryptogramType(response));
        assertArrayEquals(hex("06 01 12 03 66 10 00"), findTag(response.getData(), 0x9F10));

        // Online approval updates Last Online ATC Register
        assertArrayEquals(hex("9F 13 02 00 F1"), send("80 CA 9F 13 00").getData());

        startTransaction();
        assertArrayEquals(hex("06 01 12 03 A0 00 00"), findTag(firstGenerateAc("80").getData(), 0x9F10));

        // Previous online transaction was not completed with the second GENERATE AC
        startTransaction();
        assertArrayEquals(hex("06 01 12 03 A0 80 00"), findTag(firstGenerateAc("80").getData(), 0x9F10));
    }

    @Test
    public void commonCoreDefinitionsCardVerificationResultsTest() throws CardException, GeneralSecurityException {
        // Common Core Definitions IAD: length '0F', CCI 'A5', DKI, CVR (5), counters (8)
        assertSw(0x9000, send("80 01 9F 10 10 0F A5 01 00 00 00 00 00 00 00 00 00 00 00 00 00"));
        assertSw(0x9000, send("80 00 00 0D 02 01 03"));
        startTransaction();

        // Second GENERATE AC not requested, ARQC. PIN Try Counter 3
        ResponseAPDU response = firstGenerateAc("80");
        assertArrayEquals(hex("0F A5 01 A0 30 00 00 00 00 00 00 00 00 00 00 00"), findTag(response.getData(), 0x9F10));
        secureMessagingSessionKey = deriveSessionKey(hex(SM_MAC_MASTER_KEY), findTag(response.getData(), 0x9F26));
        secureMessagingMacChain = findTag(response.getData(), 0x9F26);

        // TC, unable to go online
        response = secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE);
        assertEquals((byte) 0x40, cryptogramType(response));
        assertArrayEquals(hex("0F A5 01 60 30 00 01 00 00 00 00 00 00 00 00 00"), findTag(response.getData(), 0x9F10));

        // Issuer script after the final GENERATE AC: two commands processed and one failed
        assertSw(0x9000, send(scriptCommand("8C 18 00 00")));
        assertSw(0x9000, send(scriptCommand("8C 18 00 00")));
        assertSw(0x6988, send("8C 18 00 00 0A 8E 08 01 02 03 04 05 06 07 08"));

        // CDA performed, 3 script commands, script processing failed, go online on next transaction was set
        startTransaction();
        response = firstGenerateAc("90");
        assertArrayEquals(hex("0F A5 01 A8 30 00 3A 00 00 00 00 00 00 00 00 00"), findTag(response.getData(), 0x9F10));
    }

    @Test
    public void consecutiveOfflineLimitsTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send(CARD_RISK_MANAGEMENT_ENABLED));
        // Lower Consecutive Offline Limit 2, Upper Consecutive Offline Limit 3
        assertSw(0x9000, send("80 01 9F 14 01 02"));
        assertSw(0x9000, send("80 01 9F 23 01 03"));

        assertEquals((byte) 0x40, offlineTransaction());
        assertEquals((byte) 0x40, offlineTransaction());

        // Lower limit exceeded, card goes online. Terminal unable to go online, upper limit is not exceeded
        assertEquals((byte) 0x80, offlineTransaction());
        assertEquals((byte) 0x40, cryptogramType(secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE)));

        // Upper limit exceeded, card declines when unable to go online
        assertEquals((byte) 0x80, offlineTransaction());
        assertEquals((byte) 0x00, cryptogramType(secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE)));

        // Online approval with issuer authentication resets the counters
        startTransaction();
        assertEquals((byte) 0x40, cryptogramType(approveOnline(firstGenerateAc("80"))));
        assertEquals((byte) 0x40, offlineTransaction());
    }

    @Test
    public void cumulativeOfflineAmountLimitsTest() throws CardException {
        assertSw(0x9000, send(CARD_RISK_MANAGEMENT_ENABLED));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 0E 06 00 00 00 00 00 02"));
        // Lower limit 0.02 and upper limit 0.03
        assertSw(0x9000, send("80 00 00 0E 0C 00 00 00 00 00 02 00 00 00 00 00 03"));

        assertEquals((byte) 0x40, offlineTransaction());
        assertEquals((byte) 0x40, offlineTransaction());

        assertEquals((byte) 0x80, offlineTransaction());
        assertEquals((byte) 0x40, cryptogramType(secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE)));

        assertEquals((byte) 0x80, offlineTransaction());
        assertEquals((byte) 0x00, cryptogramType(secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE)));
    }

    @Test
    public void cardRiskManagementDisabledTest() throws CardException {
        assertSw(0x9000, send("80 01 9F 14 01 00"));
        assertSw(0x9000, send("80 00 00 0D 02 02 03"));

        // Card follows the terminal decision, CVR indicates exceeded velocity checking counters
        startTransaction();
        ResponseAPDU response = firstGenerateAc("40");
        assertEquals((byte) 0x40, cryptogramType(response));
        assertArrayEquals(hex("06 01 12 03 90 30 00"), findTag(response.getData(), 0x9F10));
    }

    @Test
    public void offlineAccumulatorBalanceTest() throws CardException {
        assertSw(0x9000, send("80 01 9F 50 06 00 00 00 00 00 02"));
        assertSw(0x9000, send(CARD_RISK_MANAGEMENT_ENABLED));

        // Balance is readable before and after GENERATE AC
        assertArrayEquals(hex("9F 50 06 00 00 00 00 00 02"), send("80 CA 9F 50 00").getData());
        assertEquals((byte) 0x40, offlineTransaction());
        assertArrayEquals(hex("9F 50 06 00 00 00 00 00 01"), send("80 CA 9F 50 00").getData());
        assertEquals((byte) 0x40, offlineTransaction());
        assertArrayEquals(hex("9F 50 06 00 00 00 00 00 00"), send("80 CA 9F 50 00").getData());

        // Balance does not cover the amount, card goes online
        assertEquals((byte) 0x80, offlineTransaction());
    }

    @Test
    public void transactionLogTest() throws CardException {
        // Log Entry: SFI 11, 3 records. Log Format: CID, Amount, Currency, Date, ATC, Transaction Type
        assertSw(0x9000, send("80 01 9F 4D 02 0B 03"));
        assertSw(0x9000, send("80 01 9F 4F 10 9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36 02 9C 01"));
        assertArrayEquals(hex("9F 4F 10 9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36 02 9C 01"), send("80 CA 9F 4F 00").getData());

        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("00 B2 01 5C 00"));

        // Record of an online transaction is updated by the second GENERATE AC
        startTransaction();
        firstGenerateAc("80");
        assertArrayEquals(hex("80 000000000001 0978 200724 00F1 21"), send("00 B2 01 5C 00").getData());
        secondGenerateAc(ARC_UNABLE_TO_GO_ONLINE);
        assertArrayEquals(hex("40 000000000001 0978 200724 00F1 21"), send("00 B2 01 5C 00").getData());

        offlineTransaction();
        offlineTransaction();
        offlineTransaction();

        // Record 1 is the most recent, the oldest record is overwritten
        assertArrayEquals(hex("40 000000000001 0978 200724 00F4 21"), send("00 B2 01 5C 00").getData());
        assertArrayEquals(hex("40 000000000001 0978 200724 00F3 21"), send("00 B2 02 5C 00").getData());
        assertArrayEquals(hex("40 000000000001 0978 200724 00F2 21"), send("00 B2 03 5C 0F").getData());
        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("00 B2 04 5C 00"));
        assertSw(0x6C0F, SmartCard.transmitCommand(hex("00 B2 01 5C 10")));

        // Other records are not affected
        assertSw(0x9000, send("00 B2 01 14 00"));
    }

    /**
     * Enciphered PIN block for VERIFY (EMV Book 2, 7.2): '7F' || PIN block || ICC Unpredictable Number || padding.
     */
    private static byte[] encipherPin(BigInteger modulus, byte[] pinBlock, byte[] challenge) {
        int keySize = modulus.bitLength() / 8;
        byte[] padding = new byte[keySize - 17];
        Arrays.fill(padding, (byte) 0x55);

        byte[] plaintext = concat(new byte[] { (byte) 0x7F }, pinBlock, challenge, padding);
        byte[] ciphertext = new BigInteger(1, plaintext).modPow(EmvTestUtil.ICC_PUBLIC_EXPONENT, modulus).toByteArray();

        byte[] result = new byte[keySize];
        int length = Math.min(ciphertext.length, keySize);
        System.arraycopy(ciphertext, ciphertext.length - length, result, keySize - length, length);
        return result;
    }

    private static byte[] unsigned(BigInteger value, int length) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[length];
        int copyLength = Math.min(bytes.length, length);
        System.arraycopy(bytes, bytes.length - copyLength, result, length - copyLength, copyLength);
        return result;
    }

    private static ResponseAPDU verifyEncipheredPin(BigInteger modulus) throws CardException {
        byte[] challenge = send("00 84 00 00 00").getData();
        byte[] enciphered = encipherPin(modulus, hex("24 12 34 FF FF FF FF FF"), challenge);
        return SmartCard.transmitCommand(concat(hex(String.format("00 20 00 88 %02X", enciphered.length)), enciphered));
    }

    @Test
    public void pinEnciphermentKeyTest() throws CardException, GeneralSecurityException {
        // PIN key of the ICC key size, the card expects the enciphered PIN in its modulus length
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(new RSAKeyGenParameterSpec(iccModulus.bitLength(), EmvTestUtil.ICC_PUBLIC_EXPONENT));
        RSAPrivateKey pinKey;
        do {
            pinKey = (RSAPrivateKey) generator.generateKeyPair().getPrivate();
            // PIN enciphered with the ICC key must be a valid input for the PIN key
        } while (pinKey.getModulus().compareTo(iccModulus) <= 0);

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 00 00 10 01 03"));
        int keySize = (iccModulus.bitLength() + 7) / 8;
        String keyLength = String.format(" %02X", keySize);
        assertSw(0x9000, SmartCard.transmitCommand(concat(hex("80 00 00 0F" + keyLength), unsigned(pinKey.getModulus(), keySize))));
        assertSw(0x9000, SmartCard.transmitCommand(concat(hex("80 00 00 10" + keyLength), unsigned(pinKey.getPrivateExponent(), keySize))));

        // ICC PIN Encipherment Key is used instead of ICC key
        assertSw(0x9000, verifyEncipheredPin(pinKey.getModulus()));
        assertSw(ISO7816.SW_DATA_INVALID, verifyEncipheredPin(iccModulus));
        assertArrayEquals(hex("9F 17 01 03"), send("80 CA 9F 17 00").getData());

        // ICC key is used when the PIN key is cleared
        assertSw(0x9000, send("80 00 00 0F 00"));
        assertSw(0x9000, verifyEncipheredPin(iccModulus));
    }

    @Test
    public void threeByteTagTest() throws CardException {
        // Tag of three bytes is given in the command data when P1 P2 is '00 00'
        assertSw(0x9000, send("80 01 00 00 05 DF 81 01 AA BB"));
        assertSw(ISO7816.SW_DATA_INVALID, send("80 01 00 00 03 00 82 01"));
        assertSw(ISO7816.SW_DATA_INVALID, send("80 01 00 00 00"));

        // Tag lists may have one byte tags without '00' prefix and tags of three bytes
        assertSw(0x9000, send("80 02 00 01 02 82 94"));
        assertSw(0x9000, send("80 02 00 03 0B 9F 27 9F 36 9F 26 9F 10 DF 81 01"));

        assertSw(0x9000, send(SELECT));
        ResponseAPDU response = send("80 A8 00 00 02 83 00 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("77 12 82 02 3C 00 94 0C"), Arrays.copyOfRange(response.getData(), 0, 8));

        byte[] data = firstGenerateAc("80").getData();
        assertArrayEquals(hex("DF 81 01 02 AA BB"), Arrays.copyOfRange(data, data.length - 6, data.length));
    }

    @Test
    public void putDataTest() throws CardException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        // PUT DATA is supported when writable tags are configured
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("80 DA DF 61 02 12 34"));
        assertSw(0x6A88, send("80 CA DF 61 00"));

        assertSw(0x9000, send("80 00 00 11 04 DF 61 9F 50"));

        // Only after GET PROCESSING OPTIONS
        assertSw(0x9000, send(SELECT));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 DA DF 61 02 12 34"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(0x9000, send("80 DA DF 61 02 12 34"));
        assertArrayEquals(hex("DF 61 02 12 34"), send("80 CA DF 61 00").getData());
        assertSw(0x9000, send("80 DA 9F 50 06 00 00 00 00 01 00"));
        assertArrayEquals(hex("9F 50 06 00 00 00 00 01 00"), send("80 CA 9F 50 00").getData());

        // Other data can not be written
        assertSw(0x6A88, send("80 DA 00 5A 02 12 34"));

        // Written data stays after GENERATE AC
        firstGenerateAc("40");
        assertSw(0x9000, send("80 DA DF 61 02 56 78"));
        assertArrayEquals(hex("DF 61 02 56 78"), send("80 CA DF 61 00").getData());
    }

    @Test
    public void selectNextOccurrenceTest() throws CardException {
        assertSw(ISO7816.SW_FILE_NOT_FOUND, send("00 A4 04 02 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send(SELECT));
    }
}
