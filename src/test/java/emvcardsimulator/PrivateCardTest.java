package emvcardsimulator;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.smartcardio.CardException;
import javax.smartcardio.ResponseAPDU;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;

/**
 * Contact and contactless transactions of the private test cards in private/cards against emvpt, run with 'gradle testPrivateCards'.
 * The private directory is not in the repository, without it there are no tests.
 * Applets of a card are installed by the SELECT commands of its setup file.
 */
public class PrivateCardTest {
    // Tests are run in src/test/java/emvcardsimulator
    private static final Path CARDS = Paths.get("../../../../private/cards");

    private static final String PPSE_AID = "325041592E5359532E4444463031";
    private static final String PSE_AID = "315041592E5359532E4444463031";

    private static native void sendApduResponse(byte[] responseApdu);

    private static native void contactEntryPoint(PrivateCardTest callback, String setupFile);

    private static native void contactlessEntryPoint(PrivateCardTest callback, String setupFile);

    @BeforeAll
    public static void loadLibrary() {
        System.loadLibrary("simulator");
    }

    @AfterEach
    public void disconnect() throws CardException {
        SmartCard.disconnect();
        SmartCard.setLogging(true);
    }

    /**
     * Contact (T=1) and contactless transaction of each private test card.
     */
    @TestFactory
    public Stream<DynamicTest> privateCards() throws IOException {
        if (!Files.isDirectory(CARDS)) {
            return Stream.empty();
        }

        List<Path> cards;
        try (Stream<Path> files = Files.walk(CARDS)) {
            // Cards are selected by a part of their path, e.g. 'gradle testPrivateCards -PprivateCards=Cashback/cash_card_87'
            String selection = System.getProperty("privateCards", "");
            cards = files.filter(file -> file.toString().endsWith(".yaml") && CARDS.relativize(file).toString().contains(selection))
                .sorted().collect(Collectors.toList());
        }

        List<DynamicTest> tests = new ArrayList<>();
        for (Path card : cards) {
            String name = CARDS.relativize(card).toString();
            tests.add(DynamicTest.dynamicTest(name + " contact", () -> {
                install(card, SmartCard.PROTOCOL_T1);
                contactEntryPoint(this, card.toString());
            }));
            tests.add(DynamicTest.dynamicTest(name + " contactless", () -> {
                install(card, SmartCard.PROTOCOL_CONTACTLESS);
                contactlessEntryPoint(this, card.toString());
            }));
        }
        return tests.stream();
    }

    /**
     * Install the applets selected in the setup file of the card.
     */
    private static void install(Path card, String protocol) throws IOException, CardException {
        Set<String> aids = new LinkedHashSet<>();
        for (String line : Files.readAllLines(card, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (trimmed.startsWith("- req: '00 A4 04 00 ")) {
                aids.add(trimmed.substring("- req: '00 A4 04 00 ".length() + 3, trimmed.length() - 1).replace(" ", ""));
            }
        }

        SmartCard.disconnect();
        SmartCard.setLogging(false);
        SmartCard.connect(protocol);
        for (String aid : aids) {
            byte[] aidBytes = EmvTestUtil.hex(aid);
            if (PPSE_AID.equals(aid)) {
                SmartCard.install(aidBytes, ProximityPaymentSystemEnvironment.class);
            } else if (PSE_AID.equals(aid)) {
                SmartCard.install(aidBytes, PaymentSystemEnvironmentContainer.class);
            } else {
                SmartCard.install(aidBytes, PaymentApplicationContainer.class);
            }
        }
    }

    /**
     * Proxy request from Rust library to simulated JavaCard.
     */
    public void sendApduRequest(byte[] requestApdu) {
        try {
            ResponseAPDU response = SmartCard.transmitCommand(Arrays.copyOf(requestApdu, requestApdu.length));
            sendApduResponse(response.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException(e);
        }
    }
}
