package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SimulatorTest {
    private static native void sendApduResponse(byte[] responseApdu);

    private static native void entryPoint(SimulatorTest callback);

    private static native void contactDeclinedEntryPoint(SimulatorTest callback);

    private static native void contactUnableToGoOnlineEntryPoint(SimulatorTest callback);

    private static native void mastercardContactlessEntryPoint(SimulatorTest callback);

    private static native void mockstercardContactlessPinEntryPoint(SimulatorTest callback);

    private static native void visaContactlessEntryPoint(SimulatorTest callback);

    @BeforeAll
    public static void loadLibrary() {
        System.loadLibrary("simulator");
    }

    // GET RESPONSE commands of the transaction
    private int getResponseCount;

    /**
     * Setup smart card with the transport protocol for the use with the simulator.
     * @throws CardException
     */
    private void setup(String protocol) throws CardException {
        SmartCard.setLogging(false);
        SmartCard.connect(protocol);

        // 1PAY.SYS.DDF01
        byte[] pseAid = new byte[] { (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 };
        // 2PAY.SYS.DDF01
        byte[] ppseAid = new byte[] { (byte) 0x32, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 };
        byte[] aid = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,  (byte) 0xFF, (byte) 0x12, (byte) 0x34 };
        SmartCard.install(pseAid, PaymentSystemEnvironmentContainer.class);
        SmartCard.install(ppseAid, ProximityPaymentSystemEnvironment.class);
        SmartCard.install(aid, PaymentApplicationContainer.class);
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    /**
     * Contact transaction with T=1, response data is sent with the command.
     */
    @Test
    public void simulatorEndToEndTransactionTest() throws CardException {
        setup(SmartCard.PROTOCOL_T1);
        SimulatorTest.entryPoint(this);
    }

    /**
     * Contact transaction with T=0, response data of case 4 commands is sent with GET RESPONSE.
     */
    @Test
    public void simulatorEndToEndTransactionT0Test() throws CardException {
        setup(SmartCard.PROTOCOL_T0);
        SimulatorTest.entryPoint(this);
        assertTrue(getResponseCount > 0);
    }

    /**
     * Contact transaction declined by the issuer: the terminal requests an AAC in the second GENERATE AC.
     */
    @Test
    public void simulatorEndToEndDeclinedTransactionTest() throws CardException {
        setup(SmartCard.PROTOCOL_T1);
        SimulatorTest.contactDeclinedEntryPoint(this);
    }

    /**
     * Contact transaction where the terminal is unable to go online: second GENERATE AC with Authorisation Response Code 'Y3'.
     */
    @Test
    public void simulatorEndToEndUnableToGoOnlineTransactionTest() throws CardException {
        setup(SmartCard.PROTOCOL_T1);
        SimulatorTest.contactUnableToGoOnlineEntryPoint(this);
    }

    /**
     * Mastercard contactless (Kernel 2): Relay Resistance Protocol, no CVM and CDA.
     */
    @Test
    public void simulatorEndToEndMastercardContactlessTransactionTest() throws CardException {
        setup(SmartCard.PROTOCOL_CONTACTLESS);
        SimulatorTest.mastercardContactlessEntryPoint(this);
    }

    /**
     * Mockstercard, a fake card scheme on top of Kernel 2, contactless card for a demonstration: the card deciphers and
     * shows the PIN entered on the terminal.
     * The terminal deviates from Kernel 2 by doing offline PIN.
     */
    @Test
    public void simulatorEndToEndMockstercardContactlessPinTest() throws CardException {
        setup(SmartCard.PROTOCOL_CONTACTLESS);
        SimulatorTest.mockstercardContactlessPinEntryPoint(this);
    }

    /**
     * Visa contactless (Kernel 3): qVSDC with fDDA and no CVM.
     */
    @Test
    public void simulatorEndToEndVisaContactlessTransactionTest() throws CardException {
        setup(SmartCard.PROTOCOL_CONTACTLESS);
        SimulatorTest.visaContactlessEntryPoint(this);
    }

    private void printAsHex(String type, byte[] buf) {
        System.out.print(type + " (" + buf.length + " b): [");
        for (int i = 0; i < buf.length - 1; i++) {
            System.out.print(String.format("%02X, ", buf[i]));
        }
        System.out.println(String.format("%02X]", buf[buf.length - 1]));
    }

    /**
     * Proxy request from Rust library to simulated JavaCard.
     */
    public void sendApduRequest(byte[] requestApdu) {
        if (requestApdu[1] == (byte) 0xC0) {
            getResponseCount++;
        }

        try {
            ResponseAPDU response = SmartCard.transmitCommand(requestApdu);
            sendApduResponse(response.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
