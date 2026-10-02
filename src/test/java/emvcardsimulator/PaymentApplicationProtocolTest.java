package emvcardsimulator;

import static emvcardsimulator.EmvTestUtil.assertSw;
import static emvcardsimulator.EmvTestUtil.concat;
import static emvcardsimulator.EmvTestUtil.deriveSessionKey;
import static emvcardsimulator.EmvTestUtil.des;
import static emvcardsimulator.EmvTestUtil.findTag;
import static emvcardsimulator.EmvTestUtil.hex;
import static emvcardsimulator.EmvTestUtil.macAlgorithm3;
import static emvcardsimulator.EmvTestUtil.pad;
import static emvcardsimulator.EmvTestUtil.responseTlvsWithoutSdad;
import static emvcardsimulator.EmvTestUtil.retailMac;
import static emvcardsimulator.EmvTestUtil.send;
import static emvcardsimulator.EmvTestUtil.sha1;
import static emvcardsimulator.EmvTestUtil.toHex;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javacard.framework.ISO7816;
import javax.crypto.Cipher;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * EMV protocol behaviour of the payment application with the test card profile, on the contact interface with T=1.
 */
public class PaymentApplicationProtocolTest {
    private static final byte[] APPLET_AID = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0x12, (byte) 0x34 };
    private static final String SETUP_FILE = "../config/card_setup_app_apdus.yaml";

    private static final BigInteger ICC_PUBLIC_EXPONENT = EmvTestUtil.ICC_PUBLIC_EXPONENT;

    // CDOL1 of the test profile: 9F02 06, 9F03 06, 9F1A 02, 95 05, 5F2A 02, 9A 03, 9C 01, 9F37 04
    private static final String CDOL1_DATA = "000000000001 000000000000 0246 0000000000 0978 200724 21 01234567";
    // CDOL2 of the test profile: 8A 02 followed by CDOL1 data objects
    private static final String CDOL2_DATA = "5933 " + CDOL1_DATA;
    // Static Application Cryptogram of the test profile, used when MK_AC is not set
    private static final byte[] STATIC_APPLICATION_CRYPTOGRAM = hex("B0189101D11416C1");
    // ICC Application Cryptogram Master Key MK_AC of the test profile
    private static final String AC_MASTER_KEY = "0123456789ABCDEF FEDCBA9876543210";
    // AIP and Issuer Application Data of the test profile
    private static final String AIP = "3C00";
    // Issuer Application Data of Cryptogram Version Number 18, included in the Application Cryptogram
    private static final String ISSUER_APPLICATION_DATA = "06011203A4A002";
    // ATC of the first transaction after personalization
    private static final String ATC = "00F1";
    // Authorisation Response Code of CDOL2_DATA
    private static final String ARC = "5933";
    // ICC Secure Messaging for Integrity Master Key MK_SMI of the test profile
    private static final String SM_MAC_MASTER_KEY = "89ABCDEF01234567 76543210FEDCBA98";

    // Secure messaging MAC chaining value of issuer script commands
    private byte[] secureMessagingMacChain;
    // Application Cryptogram of the first GENERATE AC, included in the MAC of secure messaging format 2
    private byte[] secureMessagingApplicationCryptogram;
    private byte[] secureMessagingSessionKey;

    private BigInteger iccModulus;

    /**
     * Application Cryptogram of the test profile over data || Issuer Application Data, e.g. CDOL1 related data || AIP || ATC || IAD.
     */
    private static byte[] applicationCryptogram(byte[] atc, byte[]... data) throws GeneralSecurityException {
        return retailMac(deriveSessionKey(hex(AC_MASTER_KEY), atc), concat(concat(data), hex(ISSUER_APPLICATION_DATA)));
    }

    /**
     * ARPC Method 1, EMV Book 2 8.2.1: DES3(SK_AC)[ARQC XOR (ARC || '00' .. '00')].
     */
    private static byte[] arpcMethod1(byte[] arqc, byte[] arc) throws GeneralSecurityException {
        byte[] y = Arrays.copyOf(arqc, 8);
        y[0] ^= arc[0];
        y[1] ^= arc[1];
        return des(Cipher.ENCRYPT_MODE, deriveSessionKey(hex(AC_MASTER_KEY), hex(ATC)), y);
    }

    /**
     * ARPC Method 2, EMV Book 2 8.2.2: 4-byte MAC(SK_AC)[ARQC || CSU || Proprietary Authentication Data].
     */
    private static byte[] arpcMethod2(byte[] arqc, byte[] csu, byte[] proprietaryAuthenticationData) throws GeneralSecurityException {
        byte[] mac = retailMac(deriveSessionKey(hex(AC_MASTER_KEY), hex(ATC)), concat(arqc, csu, proprietaryAuthenticationData));
        return Arrays.copyOf(mac, 4);
    }

    /**
     * GET PROCESSING OPTIONS and first GENERATE AC requesting ARQC, returns the ARQC.
     */
    private static byte[] authorisationRequest() throws CardException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("80"), findTag(response.getData(), 0x9F27));
        return findTag(response.getData(), 0x9F26);
    }

    /**
     * Second GENERATE AC requesting TC, returns the Cryptogram Information Data after checking the Application Cryptogram.
     */
    private static byte completeTransaction(String cdol2Data) throws CardException, GeneralSecurityException {
        ResponseAPDU response = send(String.format("80 AE 40 00 %02X %s 00", hex(cdol2Data).length, cdol2Data));
        assertSw(0x9000, response);
        assertArrayEquals(applicationCryptogram(hex(ATC), hex(cdol2Data), hex(AIP), hex(ATC)), findTag(response.getData(), 0x9F26));
        return findTag(response.getData(), 0x9F27)[0];
    }

    /**
     * Start issuer script secure messaging: MAC Session Key from MK_SMI and the first Application Cryptogram (EMV Book 2, 9.2.2),
     * and the first MAC chaining value is the Application Cryptogram (EMV Book 2, 9.2.3.1).
     */
    private void startSecureMessaging(byte[] applicationCryptogram) throws GeneralSecurityException {
        secureMessagingSessionKey = deriveSessionKey(hex(SM_MAC_MASTER_KEY), applicationCryptogram);
        secureMessagingMacChain = applicationCryptogram;
        secureMessagingApplicationCryptogram = applicationCryptogram;
    }

    /**
     * Issuer script command with secure messaging format 1 (EMV Book 2, Annex D2).
     * MAC input: chaining value || header || '80 00 00 00' || padded data object
     */
    private String scriptCommand(String header, String dataObject, int macLength) throws GeneralSecurityException {
        byte[] input = concat(secureMessagingMacChain, hex(header), hex("80 00 00 00"));
        if (!dataObject.isEmpty()) {
            input = concat(input, pad(hex(dataObject)));
        }

        byte[] mac = macAlgorithm3(secureMessagingSessionKey, input);
        secureMessagingMacChain = mac;

        byte[] data = concat(hex(dataObject), new byte[] { (byte) 0x8E, (byte) macLength }, Arrays.copyOf(mac, macLength));
        return header + String.format(" %02X ", data.length) + toHex(data);
    }

    private String scriptCommand(String header) throws GeneralSecurityException {
        return scriptCommand(header, "", 8);
    }

    /**
     * Issuer script command with secure messaging format 2 (EMV Book 2, 9.2.1.2): data || 8-byte MAC, no MAC chaining.
     * MAC input: CLA INS P1 P2 Lc || ATC || Application Cryptogram || data
     */
    private String scriptCommandFormat2(String header, String data) throws GeneralSecurityException {
        byte[] lc = new byte[] { (byte) (hex(data).length + 8) };
        byte[] mac = retailMac(secureMessagingSessionKey, concat(hex(header), lc, hex(ATC), secureMessagingApplicationCryptogram, hex(data)));
        return header + " " + toHex(lc) + " " + toHex(concat(hex(data), mac));
    }

    private byte[] recoverSignedData(byte[] signature) {
        return EmvTestUtil.recoverSignedData(iccModulus, signature);
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
     * Transport protocol of the tests.
     */
    protected String protocol() {
        return SmartCard.PROTOCOL_T1;
    }

    /**
     * Personalize the card with the test profile and select the application.
     */
    @BeforeEach
    public void setup() throws CardException, IOException {
        SmartCard.setLogging(false);
        SmartCard.connect(protocol());
        SmartCard.install(APPLET_AID, PaymentApplicationContainer.class);

        iccModulus = EmvTestUtil.personalize(SETUP_FILE);

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
        // Secure messaging without header authentication
        assertSw(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED, send("88 1E 00 00 08 01 02 03 04 05 06 07 08"));
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("00 CA 9F 36 00"));
        // Secure messaging formats 1 and 2 only for issuer script commands
        assertSw(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED, send("8C CA 9F 36 00"));
        assertSw(ISO7816.SW_SECURE_MESSAGING_NOT_SUPPORTED, send("84 CA 9F 36 00"));
    }

    @Test
    public void getDataTest() throws CardException {
        ResponseAPDU response = send("80 CA 9F 36 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("9F 36 02 00 F0"), response.getData());

        assertSw(0x9000, send("80 CA 9F 36 05"));
        assertSw(0x6C05, SmartCard.transmitCommand(hex("80 CA 9F 36 02")));

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
        assertSw(0x6C00 | length, SmartCard.transmitCommand(hex(String.format("00 B2 01 14 %02X", length - 3))));

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
    public void transactionFlowTest() throws CardException, GeneralSecurityException {
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 80 00 1D " + CDOL1_DATA + " 00"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("00 82 00 00 08 12 34 56 78 12 34 56 78"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 AE 80 00 1C " + CDOL1_DATA.replace(" 01234567", " 012345") + " 00"));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 AE C0 00 1D " + CDOL1_DATA + " 00"));

        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("80"), findTag(response.getData(), 0x9F27));
        assertArrayEquals(hex(ATC), findTag(response.getData(), 0x9F36));

        String issuerAuthenticationData = toHex(arpcMethod1(findTag(response.getData(), 0x9F26), hex(ARC))) + " " + ARC;
        assertSw(ISO7816.SW_WRONG_LENGTH, send("00 82 00 00 07 12 34 56 78 12 34 56"));
        assertSw(0x9000, send("00 82 00 00 0A " + issuerAuthenticationData));
        // At most one EXTERNAL AUTHENTICATE per transaction
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("00 82 00 00 0A " + issuerAuthenticationData));

        // Second GENERATE AC completes the transaction
        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 AE 80 00 1F " + CDOL2_DATA + " 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 AE 40 00 1D " + CDOL1_DATA + " 00"));

        response = send("80 AE 40 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("40"), findTag(response.getData(), 0x9F27));
        // ATC does not change within the transaction
        assertArrayEquals(hex(ATC), findTag(response.getData(), 0x9F36));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 AE 40 00 1F " + CDOL2_DATA + " 00"));

        // New transaction after selection
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertArrayEquals(hex("9F 36 02 00 F2"), send("80 CA 9F 36 00").getData());
    }

    @Test
    public void applicationCryptogramMasterKeySettingTest() throws CardException {
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 07 08 01 23 45 67 89 AB CD EF"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 07 18 " + AC_MASTER_KEY + " 01 23 45 67 89 AB CD EF"));
        assertSw(0x9000, send("80 00 00 07 10 " + AC_MASTER_KEY));
    }

    @Test
    public void staticApplicationCryptogramWithoutMasterKeyTest() throws CardException {
        // Empty data clears the key, clearing twice is allowed
        assertSw(0x9000, send("80 00 00 07 00"));
        assertSw(0x9000, send("80 00 00 07 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(STATIC_APPLICATION_CRYPTOGRAM, findTag(response.getData(), 0x9F26));

        // Key can be set again
        assertSw(0x9000, send("80 00 00 07 10 " + AC_MASTER_KEY));
        response = send("80 AE 40 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        assertTrue(!Arrays.equals(STATIC_APPLICATION_CRYPTOGRAM, findTag(response.getData(), 0x9F26)));
    }

    @Test
    public void sessionKeyAndRetailMacReferenceTest() throws GeneralSecurityException {
        // Check the reference implementation itself against known values
        // DES key 0123456789ABCDEF, plaintext "Now is t", FIPS 81 / Handbook of Applied Cryptography example
        assertArrayEquals(hex("3FA40E8A984D4815"), des(Cipher.ENCRYPT_MODE, hex("0123456789ABCDEF"), hex("4E6F772069732074")));
        // ISO/IEC 9797-1 Algorithm 3 with padding method 2 is the same as padding followed by DES CBC-MAC and 3DES on last block
        final byte[] key = hex("0123456789ABCDEF FEDCBA9876543210");
        byte[] message = hex("00112233445566778899AABBCCDDEEFF");
        byte[] cbc = des(Cipher.ENCRYPT_MODE, hex("0123456789ABCDEF"), hex("0011223344556677"));
        for (int i = 0; i < 8; i++) {
            cbc[i] ^= message[8 + i];
        }
        cbc = des(Cipher.ENCRYPT_MODE, hex("0123456789ABCDEF"), cbc);
        cbc[0] ^= (byte) 0x80;
        assertArrayEquals(des(Cipher.ENCRYPT_MODE, key, cbc), retailMac(key, message));
    }

    @Test
    public void applicationCryptogramGenerationTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        byte[] arqc = findTag(response.getData(), 0x9F26);
        assertArrayEquals(applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC)), arqc);

        response = send("80 AE 40 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        byte[] tc = findTag(response.getData(), 0x9F26);
        assertArrayEquals(applicationCryptogram(hex(ATC), hex(CDOL2_DATA), hex(AIP), hex(ATC)), tc);

        // Session key changes with ATC
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(applicationCryptogram(hex("00 F2"), hex(CDOL1_DATA), hex(AIP), hex("00 F2")), findTag(response.getData(), 0x9F26));
        assertTrue(!Arrays.equals(arqc, findTag(response.getData(), 0x9F26)));
    }

    @Test
    public void applicationCryptogramWithoutIssuerApplicationDataTest() throws CardException, GeneralSecurityException {
        // Flags: random enabled, Issuer Application Data not included in Application Cryptogram
        assertSw(0x9000, send("80 00 00 03 02 00 01"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex(ISSUER_APPLICATION_DATA), findTag(response.getData(), 0x9F10));
        assertArrayEquals(retailMac(deriveSessionKey(hex(AC_MASTER_KEY), hex(ATC)), concat(hex(CDOL1_DATA), hex(AIP), hex(ATC))),
            findTag(response.getData(), 0x9F26));
    }

    @Test
    public void applicationCryptogramInCombinedDataAuthenticationTest() throws CardException, GeneralSecurityException, NoSuchAlgorithmException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);

        // Application Cryptogram is inside Signed Dynamic Application Data: 6A 05 01 Ldd Lidn IDN(3) CID AC
        byte[] recovered = recoverSignedData(findTag(response.getData(), 0x9F4B));
        byte[] expected = applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC));
        assertArrayEquals(expected, Arrays.copyOfRange(recovered, 9, 17));
    }

    @Test
    public void arpcMethodSettingTest() throws CardException {
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 08 02 00 01"));
        assertSw(ISO7816.SW_DATA_INVALID, send("80 00 00 08 01 03"));
        assertSw(0x9000, send("80 00 00 08 01 02"));
        assertSw(0x9000, send("80 00 00 08 01 01"));
    }

    @Test
    public void arpcMethod1ExternalAuthenticateTest() throws CardException, GeneralSecurityException {
        byte[] arqc = authorisationRequest();

        assertSw(0x9000, send("00 82 00 00 0A " + toHex(arpcMethod1(arqc, hex(ARC))) + " " + ARC));
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod1ExternalAuthenticateFailedTest() throws CardException, GeneralSecurityException {
        byte[] arqc = authorisationRequest();

        // ARPC computed for another ARC
        assertSw(0x6300, send("00 82 00 00 0A " + toHex(arpcMethod1(arqc, hex("3030"))) + " " + ARC));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("00 82 00 00 0A " + toHex(arpcMethod1(arqc, hex(ARC))) + " " + ARC));

        // Transaction is declined after failed issuer authentication
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod1WithoutArcTest() throws CardException, GeneralSecurityException {
        byte[] arqc = authorisationRequest();

        // Method 1 Issuer Authentication Data is ARPC || ARC
        assertSw(0x6300, send("00 82 00 00 08 " + toHex(arpcMethod1(arqc, hex(ARC)))));
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod2ExternalAuthenticateTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 00 00 08 01 02"));
        byte[] arqc = authorisationRequest();

        // CSU: Issuer Approves Online Transaction
        byte[] csu = hex("00 80 00 00");
        assertSw(0x9000, send("00 82 00 00 08 " + toHex(arpcMethod2(arqc, csu, new byte[0])) + " " + toHex(csu)));
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod2ProprietaryAuthenticationDataTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 00 00 08 01 02"));
        byte[] arqc = authorisationRequest();

        // CSU: Proprietary Authentication Data Included, Issuer Approves Online Transaction
        byte[] csu = hex("80 80 00 00");
        byte[] proprietaryAuthenticationData = hex("01 02 03 04 05 06 07 08");
        assertSw(0x9000, send("00 82 00 00 10 " + toHex(arpcMethod2(arqc, csu, proprietaryAuthenticationData))
            + " " + toHex(csu) + " " + toHex(proprietaryAuthenticationData)));
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod2ProprietaryAuthenticationDataNotIncludedTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 00 00 08 01 02"));
        byte[] arqc = authorisationRequest();

        // Proprietary Authentication Data is not protected by ARPC when the CSU does not indicate it
        byte[] csu = hex("00 80 00 00");
        assertSw(0x9000, send("00 82 00 00 0A " + toHex(arpcMethod2(arqc, csu, new byte[0])) + " " + toHex(csu) + " 01 02"));
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcMethod2ExternalAuthenticateFailedTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 00 00 08 01 02"));
        byte[] arqc = authorisationRequest();

        // CSU changed after the ARPC was generated
        byte[] arpc = arpcMethod2(arqc, hex("00 80 00 00"), new byte[0]);
        assertSw(0x6300, send("00 82 00 00 08 " + toHex(arpc) + " 00 80 00 01"));
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void arpcInSecondGenerateAcTest() throws CardException, GeneralSecurityException {
        // Common Core Definitions: CDOL2 includes ARC and Issuer Authentication Data
        assertSw(0x9000, send("80 01 00 8D 19 8A 02 91 08 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04"));
        assertSw(0x9000, send("80 00 00 08 01 02"));
        byte[] arqc = authorisationRequest();

        byte[] csu = hex("00 80 00 00");
        String issuerAuthenticationData = toHex(arpcMethod2(arqc, csu, new byte[0])) + " " + toHex(csu);
        assertEquals((byte) 0x40, completeTransaction(ARC + " " + issuerAuthenticationData + " " + CDOL1_DATA));
    }

    @Test
    public void arpcInSecondGenerateAcFailedTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 01 00 8D 19 8A 02 91 08 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04"));
        assertSw(0x9000, send("80 00 00 08 01 02"));
        authorisationRequest();

        assertEquals((byte) 0x00, completeTransaction(ARC + " 12 34 56 78 00 80 00 00 " + CDOL1_DATA));
    }

    @Test
    public void arpcNotReceivedInSecondGenerateAcTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 01 00 8D 19 8A 02 91 08 9F 02 06 9F 03 06 9F 1A 02 95 05 5F 2A 02 9A 03 9C 01 9F 37 04"));
        assertSw(0x9000, send("80 00 00 08 01 02"));
        authorisationRequest();

        // Terminal fills missing Issuer Authentication Data with zeros, e.g. when unable to go online
        assertEquals((byte) 0x40, completeTransaction("5A33 00 00 00 00 00 00 00 00 " + CDOL1_DATA));
    }

    @Test
    public void secureMessagingReferenceTest() throws GeneralSecurityException {
        // Session key derivation with 8-byte diversification value replaces the third byte, EMV Book 2 A1.3.1
        byte[] r = hex("11 22 33 44 55 66 77 88");
        byte[] expected = concat(
            des(Cipher.ENCRYPT_MODE, hex(SM_MAC_MASTER_KEY), hex("11 22 F0 44 55 66 77 88")),
            des(Cipher.ENCRYPT_MODE, hex(SM_MAC_MASTER_KEY), hex("11 22 0F 44 55 66 77 88")));
        assertArrayEquals(expected, deriveSessionKey(hex(SM_MAC_MASTER_KEY), r));

        // Padding is always added
        assertArrayEquals(hex("01 02 03 04 05 06 07 80"), pad(hex("01 02 03 04 05 06 07")));
        assertArrayEquals(hex("01 02 03 04 05 06 07 08 80 00 00 00 00 00 00 00"), pad(hex("01 02 03 04 05 06 07 08")));
    }

    @Test
    public void scriptApplicationBlockTest() throws CardException, GeneralSecurityException {
        startSecureMessaging(authorisationRequest());

        // Tag 71 script before the second GENERATE AC
        assertSw(0x9000, send(scriptCommand("8C 1E 00 00")));

        // Blocked application returns only AAC
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));

        // SELECT returns 'Selected file invalidated', application stays selected
        assertSw(0x6283, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("00"), findTag(response.getData(), 0x9F27));

        // Tag 72 script after the final GENERATE AC, session key from the AAC of this transaction
        startSecureMessaging(findTag(response.getData(), 0x9F26));
        assertSw(0x9000, send(scriptCommand("8C 18 00 00")));

        response = send("00 A4 04 00 07 AF FF FF FF FF 12 34 00");
        assertSw(0x9000, response);
        assertEquals((byte) 0x6F, response.getData()[0]);
    }

    @Test
    public void scriptMacChainingTest() throws CardException, GeneralSecurityException {
        startSecureMessaging(authorisationRequest());

        // MAC of the second command is chained from the full MAC of the first, also when MAC is truncated to 4 bytes
        assertSw(0x9000, send(scriptCommand("8C 1E 00 00", "", 4)));
        assertSw(0x9000, send(scriptCommand("8C 18 00 00", "", 4)));
        assertSw(0x9000, send(scriptCommand("8C 24 00 00", "", 8)));

        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
    }

    @Test
    public void scriptMacFailureTest() throws CardException, GeneralSecurityException {
        byte[] arqc = authorisationRequest();

        // MAC not chained from the Application Cryptogram
        startSecureMessaging(arqc);
        secureMessagingMacChain = new byte[8];
        assertSw(0x6988, send(scriptCommand("8C 1E 00 00")));

        // MAC for another command
        startSecureMessaging(arqc);
        String applicationUnblock = scriptCommand("8C 18 00 00");
        assertSw(0x6988, send("8C 1E" + applicationUnblock.substring("8C 18".length())));

        // MAC data object missing or malformed
        assertSw(0x6987, send("8C 1E 00 00 04 81 02 01 02"));
        assertSw(0x6988, send("8C 1E 00 00 05 8E 03 01 02 03"));
        assertSw(0x6988, send("8C 1E 00 00 0A 8E 09 01 02 03 04 05 06 07 08"));
        assertSw(0x6988, send("8C 1E 00 00 0A 82 08 01 02 03 04 05 06 07 08"));

        // Application was not blocked
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
    }

    @Test
    public void scriptConditionsTest() throws CardException, GeneralSecurityException {
        // Script commands are processed only after the first GENERATE AC
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("8C 1E 00 00 0A 8E 08 01 02 03 04 05 06 07 08"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("8C 1E 00 00 0A 8E 08 01 02 03 04 05 06 07 08"));

        // MK_SMI is required
        assertSw(0x9000, send("80 00 00 09 00"));
        ResponseAPDU response = send("80 AE 80 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        byte[] arqc = findTag(response.getData(), 0x9F26);
        startSecureMessaging(arqc);
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send(scriptCommand("8C 1E 00 00")));

        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 09 08 01 23 45 67 89 AB CD EF"));
        assertSw(0x9000, send("80 00 00 09 10 " + SM_MAC_MASTER_KEY));

        // Rejected command did not advance the MAC chain
        startSecureMessaging(arqc);
        assertSw(0x9000, send(scriptCommand("8C 1E 00 00")));
    }

    @Test
    public void scriptIncorrectParametersTest() throws CardException, GeneralSecurityException {
        startSecureMessaging(authorisationRequest());

        assertSw(ISO7816.SW_INCORRECT_P1P2, send(scriptCommand("8C 1E 00 01")));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send(scriptCommand("8C 18 01 00")));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send(scriptCommand("8C 16 00 01")));
        // PIN change is payment system specific
        assertSw(ISO7816.SW_INCORRECT_P1P2, send(scriptCommand("8C 24 00 01", "87 09 01 01 02 03 04 05 06 07 08", 8)));
        assertSw(ISO7816.SW_INCORRECT_P1P2, send(scriptCommand("8C 24 00 02", "87 09 01 01 02 03 04 05 06 07 08", 8)));

        // MAC chain continues after rejected commands
        assertSw(0x9000, send(scriptCommand("8C 1E 00 00")));
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void scriptCardBlockTest() throws CardException, GeneralSecurityException {
        try {
            startSecureMessaging(authorisationRequest());
            assertSw(0x9000, send(scriptCommand("8C 16 00 00")));

            // All applications are disabled, also SELECT returns 'Function not supported'
            assertSw(ISO7816.SW_FUNC_NOT_SUPPORTED, send("80 AE 40 00 1F " + CDOL2_DATA + " 00"));
            assertSw(ISO7816.SW_FUNC_NOT_SUPPORTED, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
            assertSw(ISO7816.SW_FUNC_NOT_SUPPORTED, send("80 A8 00 00 02 83 00 00"));
            assertSw(ISO7816.SW_FUNC_NOT_SUPPORTED, send("80 CA 9F 36 00"));
        } finally {
            // Simulator factory reset removes the card block
            assertSw(0x9000, send("80 05 00 00 00"));
        }
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
    }

    @Test
    public void scriptPinUnblockTest() throws CardException, GeneralSecurityException {
        assertSw(0x63C2, send("00 20 00 80 08 24 12 35 FF FF FF FF FF"));
        assertSw(0x63C1, send("00 20 00 80 08 24 12 35 FF FF FF FF FF"));
        assertSw(0x6983, send("00 20 00 80 08 24 12 35 FF FF FF FF FF"));
        assertSw(0x6983, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));

        startSecureMessaging(authorisationRequest());
        assertSw(0x9000, send(scriptCommand("8C 24 00 00")));

        // PIN Try Counter is reset to PIN Try Limit
        assertArrayEquals(hex("9F 17 01 03"), send("80 CA 9F 17 00").getData());
        assertSw(0x9000, send("00 20 00 80 08 24 12 34 FF FF FF FF FF"));
    }

    @Test
    public void scriptFormat2ApplicationBlockTest() throws CardException, GeneralSecurityException {
        startSecureMessaging(authorisationRequest());

        // Payment system issuer scripts use secure messaging format 2, EMV Book 3 6.5.1 allows CLA '8C' or '84'
        assertSw(0x9000, send(scriptCommandFormat2("84 1E 00 00", "")));
        assertEquals((byte) 0x00, completeTransaction(CDOL2_DATA));
        assertSw(0x6283, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
    }

    @Test
    public void scriptFormat2Test() throws CardException, GeneralSecurityException {
        final byte[] record = send("00 B2 01 14 00").getData();
        startSecureMessaging(authorisationRequest());

        // MAC is not chained: the same command with the same MAC is accepted again, also mixed with format 1 commands
        String applicationUnblock = scriptCommandFormat2("84 18 00 00", "");
        assertSw(0x9000, send(applicationUnblock));
        assertSw(0x9000, send(scriptCommand("8C 18 00 00")));
        assertSw(0x9000, send(applicationUnblock));
        assertSw(0x9000, send(scriptCommandFormat2("84 24 00 00", "")));

        // Data before the MAC is protected, placeholders accept the command without changing data
        assertSw(0x9000, send(scriptCommandFormat2("04 DA 9F 36", "12 34")));
        assertSw(0x9000, send(scriptCommandFormat2("84 DC 01 14", "70 03 9F 36 00")));
        String putData = scriptCommandFormat2("04 DA 9F 36", "12 34");
        assertSw(0x6988, send(putData.replace(" 12 34 ", " 12 35 ")));

        // MAC for another command
        assertSw(0x6988, send("84 1E" + applicationUnblock.substring("84 18".length())));
        // MAC missing
        assertSw(0x6987, send("84 1E 00 00 04 01 02 03 04"));

        assertArrayEquals(hex("9F 36 02 00 F1"), send("80 CA 9F 36 00").getData());
        assertArrayEquals(record, send("00 B2 01 14 00").getData());
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
    }

    @Test
    public void scriptPutDataAndUpdateRecordPlaceholderTest() throws CardException, GeneralSecurityException {
        final byte[] record = send("00 B2 01 14 00").getData();
        startSecureMessaging(authorisationRequest());

        // Accepted with a valid MAC, but data is not changed
        assertSw(0x9000, send(scriptCommand("0C DA 9F 36", "81 02 12 34", 8)));
        assertSw(0x9000, send(scriptCommand("8C DA 9F 36", "81 02 12 34", 4)));
        assertSw(0x9000, send(scriptCommand("0C DC 01 14", "81 03 70 01 00", 8)));
        assertSw(0x9000, send(scriptCommand("8C DC 01 14", "B3 05 9F 36 02 12 34", 8)));
        assertSw(0x6988, send("0C DA 9F 36 0E 81 02 12 34 8E 08 01 02 03 04 05 06 07 08"));

        assertArrayEquals(hex("9F 36 02 00 F1"), send("80 CA 9F 36 00").getData());
        assertArrayEquals(record, send("00 B2 01 14 00").getData());
        assertEquals((byte) 0x40, completeTransaction(CDOL2_DATA));
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
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(concat(hex(String.format("00 20 00 88 %02X", enciphered.length)), enciphered)));

        assertSw(0x6C08, SmartCard.transmitCommand(hex("00 84 00 00 04")));

        ResponseAPDU response = send("00 84 00 00 00");
        assertSw(0x9000, response);
        assertEquals(8, response.getData().length);

        enciphered = encipherPin(pinBlock, response.getData());
        assertSw(ISO7816.SW_WRONG_LENGTH, SmartCard.transmitCommand(concat(hex("00 20 00 88 7F"), Arrays.copyOf(enciphered, 0x7F))));
        assertSw(0x9000, SmartCard.transmitCommand(concat(hex(String.format("00 20 00 88 %02X", enciphered.length)), enciphered)));

        // ICC Unpredictable Number is single use
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(concat(hex(String.format("00 20 00 88 %02X", enciphered.length)), enciphered)));

        response = send("00 84 00 00 00");
        enciphered = encipherPin(hex("24 43 21 FF FF FF FF FF"), response.getData());
        assertSw(0x63C2, SmartCard.transmitCommand(concat(hex(String.format("00 20 00 88 %02X", enciphered.length)), enciphered)));
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

    private void assertCombinedDataAuthentication(byte[] template, byte cryptogramType, byte[] applicationCryptogram, byte[] transactionData)
        throws NoSuchAlgorithmException {
        assertCombinedDataAuthentication(template, cryptogramType, applicationCryptogram, transactionData, new byte[0]);
    }

    /**
     * Check CDA signature, relayResistanceData is empty when the Relay Resistance Protocol was not performed.
     */
    private void assertCombinedDataAuthentication(byte[] template, byte cryptogramType, byte[] applicationCryptogram, byte[] transactionData,
        byte[] relayResistanceData) throws NoSuchAlgorithmException {
        // Application Cryptogram is inside the signature
        assertEquals(null, findTag(template, 0x9F26));
        assertArrayEquals(new byte[] { cryptogramType }, findTag(template, 0x9F27));

        byte[] recovered = recoverSignedData(findTag(template, 0x9F4B));
        int length = recovered.length;
        assertArrayEquals(hex("6A 05 01"), Arrays.copyOfRange(recovered, 0, 3));
        assertEquals((byte) 0xBC, recovered[length - 1]);

        // ICC Dynamic Data
        assertEquals(1 + 3 + 1 + 8 + 20 + relayResistanceData.length, recovered[3]);
        assertEquals(3, recovered[4]);
        assertEquals(cryptogramType, recovered[8]);
        assertArrayEquals(applicationCryptogram, Arrays.copyOfRange(recovered, 9, 17));

        byte[] transactionDataHashCode = sha1(transactionData, responseTlvsWithoutSdad(template));
        assertArrayEquals(transactionDataHashCode, Arrays.copyOfRange(recovered, 17, 37));
        // EMV Contactless Book C-2, Table 6.8 ICC Dynamic Data (RRP)
        assertArrayEquals(relayResistanceData, Arrays.copyOfRange(recovered, 37, 37 + relayResistanceData.length));

        byte[] hash = sha1(Arrays.copyOfRange(recovered, 1, length - 21), hex("01 23 45 67"));
        assertArrayEquals(hash, Arrays.copyOfRange(recovered, length - 21, length - 1));
    }

    @Test
    public void combinedDataAuthenticationTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x80,
            applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC)), hex(CDOL1_DATA));

        response = send("80 AE 50 00 1F " + CDOL2_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x40,
            applicationCryptogram(hex(ATC), hex(CDOL2_DATA), hex(AIP), hex(ATC)), concat(hex(CDOL1_DATA), hex(CDOL2_DATA)));
    }

    @Test
    public void getResponseTest() throws CardException, GeneralSecurityException {
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(hex("00 C0 00 00 00")));

        // CDA response with the 1984 bit ICC key signature does not fit a single response
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        ResponseAPDU response = SmartCard.transmitCommand(hex("80 AE 90 00 1D " + CDOL1_DATA + " 00"));
        if (SmartCard.isProtocolT0()) {
            // No response data with a case 4 command
            assertSw(0x6100, response);
            assertEquals(0, response.getData().length);
            response = SmartCard.transmitCommand(hex("00 C0 00 00 00"));
        }
        assertEquals(0x61, response.getSW1());
        assertEquals(255, response.getData().length);
        byte[] template = response.getData();
        int remaining = response.getSW2();
        assertArrayEquals(hex("77 82"), Arrays.copyOfRange(template, 0, 2));
        assertEquals(4 + ((template[2] & 0xFF) << 8 | (template[3] & 0xFF)), 255 + remaining);

        assertSw(ISO7816.SW_INCORRECT_P1P2, SmartCard.transmitCommand(hex("00 C0 01 00 00")));

        // Le limits the part length
        response = SmartCard.transmitCommand(hex("00 C0 00 00 02"));
        assertSw(0x6100 | (remaining - 2), response);
        template = concat(template, response.getData());

        response = SmartCard.transmitCommand(hex(String.format("00 C0 00 00 %02X", remaining - 2)));
        assertSw(0x9000, response);
        template = concat(template, response.getData());
        assertEquals(255 + remaining, template.length);
        assertCombinedDataAuthentication(template, (byte) 0x80,
            applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC)), hex(CDOL1_DATA));

        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(hex("00 C0 00 00 00")));
    }

    @Test
    public void getResponseDiscardedByNextCommandTest() throws CardException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertEquals(0x61, SmartCard.transmitCommand(hex("80 AE 90 00 1D " + CDOL1_DATA + " 00")).getSW1());

        assertSw(0x9000, send("80 CA 9F 36 00"));
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, SmartCard.transmitCommand(hex("00 C0 00 00 00")));
    }

    @Test
    public void combinedDataAuthenticationWithPdolTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 01 9F 38 06 9F 1A 02 9F 37 04"));
        assertSw(0x9000, send("80 A8 00 00 08 83 06 02 46 01 23 45 67 00"));

        ResponseAPDU response = send("80 AE 50 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x40,
            applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC)), concat(hex("02 46 01 23 45 67"), hex(CDOL1_DATA)));
    }

    @Test
    public void combinedDataAuthenticationNotForAacTest() throws CardException, GeneralSecurityException {
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        ResponseAPDU response = send("80 AE 10 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex("00"), findTag(response.getData(), 0x9F27));
        assertArrayEquals(applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP), hex(ATC)), findTag(response.getData(), 0x9F26));
        assertTrue(findTag(response.getData(), 0x9F4B) == null);
    }

    // AIP of the test profile with 'Relay resistance protocol is supported'
    private static final String AIP_RRP = "3C01";
    // Default relay resistance timing: min 0.0 ms, max 20.0 ms, Device Estimated Transmission Time 1.8 ms
    private static final String RELAY_RESISTANCE_TIMING = "0000 00C8 0012";

    private static void enableRelayResistanceProtocol() throws CardException {
        assertSw(0x9000, send("80 01 00 82 02 " + AIP_RRP));
    }

    /**
     * EXCHANGE RELAY RESISTANCE DATA, returns the Device Relay Resistance Entropy after checking the response format.
     */
    private static byte[] exchangeRelayResistanceData(String terminalEntropy, String timing) throws CardException {
        ResponseAPDU response = send("80 EA 00 00 04 " + terminalEntropy + " 00");
        assertSw(0x9000, response);
        byte[] data = response.getData();
        assertArrayEquals(hex("80 0A"), Arrays.copyOfRange(data, 0, 2));
        assertEquals(12, data.length);
        assertArrayEquals(hex(timing), Arrays.copyOfRange(data, 6, 12));
        return Arrays.copyOfRange(data, 2, 6);
    }

    @Test
    public void relayResistanceProtocolNotSupportedTest() throws CardException {
        // AIP of the test profile does not indicate RRP
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertSw(ISO7816.SW_INS_NOT_SUPPORTED, send("80 EA 00 00 04 01 23 45 67 00"));
    }

    @Test
    public void exchangeRelayResistanceDataTest() throws CardException {
        enableRelayResistanceProtocol();

        // Only after GET PROCESSING OPTIONS
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 EA 00 00 04 01 23 45 67 00"));

        ResponseAPDU response = send("80 A8 00 00 02 83 00 00");
        assertSw(0x9000, response);
        assertArrayEquals(hex(AIP_RRP), findTag(response.getData(), 0x82));

        assertSw(ISO7816.SW_INCORRECT_P1P2, send("80 EA 01 00 04 01 23 45 67 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 EA 00 00 03 01 23 45 00"));
        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 EA 00 00 05 01 23 45 67 89 00"));

        // Terminal may retry with a new entropy, the card responds with a new Device Relay Resistance Entropy
        byte[] first = exchangeRelayResistanceData("01 23 45 67", RELAY_RESISTANCE_TIMING);
        byte[] second = exchangeRelayResistanceData("89 AB CD EF", RELAY_RESISTANCE_TIMING);
        assertTrue(!Arrays.equals(first, second));

        assertSw(0x9000, send("80 AE 80 00 1D " + CDOL1_DATA + " 00"));

        // Not after GENERATE AC
        assertSw(ISO7816.SW_CONDITIONS_NOT_SATISFIED, send("80 EA 00 00 04 01 23 45 67 00"));
    }

    @Test
    public void relayResistanceTimingSettingTest() throws CardException {
        enableRelayResistanceProtocol();

        assertSw(ISO7816.SW_WRONG_LENGTH, send("80 00 00 0A 04 00 10 00 50"));
        assertSw(0x9000, send("80 00 00 0A 06 00 10 00 50 00 0C"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        exchangeRelayResistanceData("01 23 45 67", "0010 0050 000C");
    }

    @Test
    public void relayResistanceDeviceEntropyWithoutRandomTest() throws CardException {
        enableRelayResistanceProtocol();
        assertSw(0x9000, send("80 00 00 03 02 00 00"));

        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        assertArrayEquals(hex("AB AB AB AB"), exchangeRelayResistanceData("01 23 45 67", RELAY_RESISTANCE_TIMING));
    }

    @Test
    public void combinedDataAuthenticationWithRelayResistanceTest() throws CardException, GeneralSecurityException {
        enableRelayResistanceProtocol();
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));

        // Relay resistance data of the latest exchange is signed, its Terminal Relay Resistance Entropy is the Unpredictable Number
        exchangeRelayResistanceData("89 AB CD EF", RELAY_RESISTANCE_TIMING);
        byte[] deviceEntropy = exchangeRelayResistanceData("01 23 45 67", RELAY_RESISTANCE_TIMING);

        ResponseAPDU response = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x80,
            applicationCryptogram(hex(ATC), hex(CDOL1_DATA), hex(AIP_RRP), hex(ATC)), hex(CDOL1_DATA),
            concat(hex("01 23 45 67"), deviceEntropy, hex(RELAY_RESISTANCE_TIMING)));

        // Relay resistance data is not signed in the next transaction without the exchange
        assertSw(0x9000, send("00 A4 04 00 07 AF FF FF FF FF 12 34 00"));
        assertSw(0x9000, send("80 A8 00 00 02 83 00 00"));
        byte[] atc = hex("00 F2");
        response = send("80 AE 90 00 1D " + CDOL1_DATA + " 00");
        assertSw(0x9000, response);
        assertCombinedDataAuthentication(response.getData(), (byte) 0x80,
            applicationCryptogram(atc, hex(CDOL1_DATA), hex(AIP_RRP), atc), hex(CDOL1_DATA));
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
            "80 0E 3C 00 08 02 02 00 10 01 03 00 18 01 02 01",
            "80 CA 9F 36 00",
            "9F 36 02 00 F6",
        };
        if (SmartCard.isProtocolT0()) {
            // Response data of the case 4 command with GET RESPONSE, case 2 command sent again with the response length
            expectedLog = new String[] {
                "80 A8 00 00 02 83 00",
                "61 10",
                "00 C0 00 00 10",
                "80 0E 3C 00 08 02 02 00 10 01 03 00 18 01 02 01",
                "80 CA 9F 36 00",
                "6C 05",
                "80 CA 9F 36 05",
                "9F 36 02 00 F6",
            };
        }

        for (String expected : expectedLog) {
            ResponseAPDU response = send("80 06 00 00 00");
            assertSw(0x9000, response);
            assertArrayEquals(hex(expected), response.getData());
        }

        assertSw(ISO7816.SW_RECORD_NOT_FOUND, send("80 06 00 00 00"));
    }
}
