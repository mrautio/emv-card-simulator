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

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class SimulatorTest {
    private static native void sendApduResponse(byte[] responseApdu);

    private static native void entryPoint(SimulatorTest callback);

    /**
     * Setup smart card for the use with the simulator.
     * @throws CardException
     */
    @BeforeAll
    public static void setup() throws CardException {
        System.loadLibrary("simulator");

        SmartCard.setLogging(false);
        SmartCard.connect();

        // 1PAY.SYS.DDF01
        byte[] pseAid = new byte[] { (byte) 0x31, (byte) 0x50, (byte) 0x41, (byte) 0x59, (byte) 0x2E, (byte) 0x53, (byte) 0x59, (byte) 0x53, (byte) 0x2E, (byte) 0x44, (byte) 0x44, (byte) 0x46, (byte) 0x30, (byte) 0x31 };
        byte[] aid = new byte[] { (byte) 0xAF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,  (byte) 0xFF, (byte) 0x12, (byte) 0x34 };
        SmartCard.install(pseAid, PaymentSystemEnvironmentContainer.class);
        SmartCard.install(aid, PaymentApplicationContainer.class);
    }

    @AfterAll
    public static void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    @Test
    public void simulatorEndToEndTransactionTest() {
        SimulatorTest.entryPoint(new SimulatorTest());
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
        } catch (CardException e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
