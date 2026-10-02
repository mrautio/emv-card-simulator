package emvcardsimulator;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.licel.jcardsim.utils.AIDUtil;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class SimulatorTest {
    private static native void sendApduResponse(byte[] responseApdu);

    private static native void entryPoint(SimulatorTest callback);

    private static native void mastercardContactlessEntryPoint(SimulatorTest callback);

    private static native void visaContactlessEntryPoint(SimulatorTest callback);

    @BeforeAll
    public static void loadLibrary() {
        System.loadLibrary("simulator");
    }

    /**
     * Setup smart card for the use with the simulator.
     * @throws CardException
     */
    @BeforeEach
    public void setup() throws CardException {
        SmartCard.setLogging(false);
        SmartCard.connect();

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

    @Test
    public void simulatorEndToEndTransactionTest() {
        SimulatorTest.entryPoint(new SimulatorTest());
    }

    /**
     * Mastercard contactless (Kernel 2): Relay Resistance Protocol, enciphered offline PIN and CDA.
     */
    @Test
    public void simulatorEndToEndMastercardContactlessTransactionTest() {
        SimulatorTest.mastercardContactlessEntryPoint(new SimulatorTest());
    }

    /**
     * Visa contactless (Kernel 3): qVSDC with fDDA and no CVM.
     */
    @Test
    public void simulatorEndToEndVisaContactlessTransactionTest() {
        SimulatorTest.visaContactlessEntryPoint(new SimulatorTest());
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
        try {
            ResponseAPDU response = SmartCard.transmitCommand(requestApdu);
            sendApduResponse(response.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
