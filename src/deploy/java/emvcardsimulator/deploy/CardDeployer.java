package emvcardsimulator.deploy;

import java.io.PrintStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * Installs CAP files to a Global Platform SmartCard using the GlobalPlatformPro library, but with
 * the PC/SC connection made here instead of by the gp command line tool.
 *
 * <p>This is to enable compatibility across different platforms like MacOS and Windows
 * where low level PC/SC handling might differ.
 */
public final class CardDeployer {

    private static final String MACOS_PCSC =
            "/System/Library/Frameworks/PCSC.framework/Versions/Current/PCSC";

    // SELECT by empty AID. Read-only, answered by every Global Platform card, so it tells whether
    // a protocol can carry APDUs at all.
    private static final byte[] SELECT_ISD = {0x00, (byte) 0xA4, 0x04, 0x00, 0x00};

    // "*" lets the driver negotiate, which is correct on most setups and is tried first to keep the
    // behaviour of the gp tool. The explicit protocols are the fallbacks.
    private static final String[] PROTOCOLS = {"*", "T=0", "T=1"};

    private final PrintStream out;

    private CardDeployer(PrintStream out) {
        this.out = out;
    }

    /**
     * Installs the CAP files given as arguments, or only lists the card contents if there are none.
     *
     * @param args CAP file paths
     */
    public static void main(String[] args) throws Exception {
        CardDeployer deployer = new CardDeployer(System.out);
        deployer.run(args);
    }

    private void run(String[] args) throws Exception {
        if (args.length > 0 && "check".equals(args[0])) {
            selfCheck(Arrays.copyOfRange(args, 1, args.length));
            return;
        }

        useMacosPcscLibrary();

        Card card = connect(selectTerminal(System.getProperty("deploy.reader", "")));
        out.println("# card: " + hex(card.getATR().getBytes()) + ", protocol: " + card.getProtocol());

        Object bibo = callStatic(gpClass("apdu4j.pcsc.CardBIBO", "apdu4j.CardBIBO"), "wrap", card);
        try {
            Class<?> sessionClass = gpClass("pro.javacard.gp.GPSession");
            Object session = callStatic(sessionClass, "discover", biboArgument(bibo));
            out.println("# issuer security domain: " + call(session, "getAID"));

            Object keys = callStatic(gpClass("pro.javacard.gp.keys.PlaintextKeys",
                    "pro.javacard.gp.PlaintextKeys"), "defaultKey");
            call(session, "openSecureChannel", keys, null, null,
                    sessionClass.getField("defaultMode").get(null));
            out.println("# secure channel: " + call(session, "getSecureChannel"));

            for (String aid : commaSeparated(System.getProperty("deploy.delete", ""))) {
                out.println("# deleting " + aid);
                call(session, "deleteAID", aid(aid), Boolean.TRUE);
            }

            for (String capPath : args) {
                install(session, capPath);
            }

            out.println("# card contents:");
            callStatic(gpClass("pro.javacard.gp.GPCommands"), "listRegistry",
                    call(session, "getRegistry"), out, Boolean.TRUE);
        } finally {
            call(bibo, "close");
        }
    }

    // Verifies that every GlobalPlatformPro class, method and constant the deployment needs is
    // present in the gp.jar on the classpath, and that the CAP files parse with it. Needs no card,
    // so it tells whether a gp_version and deploy_java_version combination is usable at all.
    private void selfCheck(String[] capPaths) throws Exception {
        final Class<?> session = gpClass("pro.javacard.gp.GPSession");
        final Class<?> capFile = gpClass("pro.javacard.capfile.CAPFile", "pro.javacard.CAPFile");
        final Class<?> cardBibo = gpClass("apdu4j.pcsc.CardBIBO", "apdu4j.CardBIBO");

        findMethod(cardBibo, "wrap", 1);
        findMethod(cardBibo, "close", 0);
        findMethod(session, "openSecureChannel", 4);
        findMethod(session, "loadCapFile", 3);
        findMethod(session, "installAndMakeSelectable", 5);
        findMethod(session, "deleteAID", 2);
        findMethod(session, "getAID", 0);
        findMethod(session, "getSecureChannel", 0);
        findMethod(session, "getRegistry", 0);
        findMethod(gpClass("pro.javacard.gp.keys.PlaintextKeys", "pro.javacard.gp.PlaintextKeys"),
                "defaultKey", 0);
        findMethod(gpClass("pro.javacard.gp.GPCommands"), "listRegistry", 3);
        findMethod(capFile, "fromBytes", 1);
        session.getField("defaultMode").get(null);
        lfdbh("SHA256");
        lfdbh("SHA1");
        aid("A000000003101001");

        // Older releases take an APDUBIBO, which the card connection is then wrapped in
        Class<?> discoverParameter = findMethod(session, "discover", 1).getParameterTypes()[0];
        if (!discoverParameter.isAssignableFrom(cardBibo)) {
            gpClass("apdu4j.APDUBIBO").getConstructors();
        }

        out.println("# gp.jar on the classpath is usable on this JDK");
        out.println("#   java " + System.getProperty("java.version"));
        out.println("#   " + session.getName() + ".discover(" + discoverParameter.getName() + ")");
        out.println("#   " + capFile.getName() + ", " + cardBibo.getName());

        for (String capPath : capPaths) {
            Object cap = callStatic(capFile, "fromBytes", Files.readAllBytes(Paths.get(capPath)));
            out.println("# " + capPath + ": package " + call(cap, "getPackageAID") + ", applets "
                    + call(cap, "getAppletAIDs"));
        }
    }

    private void install(Object session, String capPath) throws Exception {
        Object cap = callStatic(gpClass("pro.javacard.capfile.CAPFile", "pro.javacard.CAPFile"),
                "fromBytes", Files.readAllBytes(Paths.get(capPath)));
        Object packageAid = call(cap, "getPackageAID");
        out.println();
        out.println("# " + capPath + ": package " + packageAid + ", applets "
                + call(cap, "getAppletAIDs"));

        // The gp tool is called with --force by the deploy tasks, which first removes an earlier
        // copy of the same package. A card without it answers 0x6A88, which is not an error here.
        if (Boolean.parseBoolean(System.getProperty("deploy.force", "true"))) {
            try {
                call(session, "deleteAID", packageAid, Boolean.TRUE);
                out.println("#   removed the previously installed package");
            } catch (InvocationTargetException e) {
                out.println("#   nothing to remove (" + e.getCause().getMessage() + ")");
            }
        }

        loadCapFile(session, cap);
        out.println("#   loaded");

        for (Object appletAid : (List<?>) call(cap, "getAppletAIDs")) {
            call(session, "installAndMakeSelectable", packageAid, appletAid, appletAid,
                    Collections.emptySet(), null);
            out.println("#   installed and made selectable: " + appletAid);
        }
    }

    // Cards that predate Global Platform 2.2 reject a SHA-256 load file data block hash with
    // 0x6A80, so the stronger hash is attempted first and SHA-1 is the fallback. Nothing is loaded
    // when INSTALL [for load] fails, so retrying is safe.
    private void loadCapFile(Object session, Object cap) throws Exception {
        String configured = System.getProperty("deploy.lfdbh", "auto");
        List<String> hashes = "auto".equals(configured)
                ? Arrays.asList("SHA256", "SHA1")
                : Collections.singletonList(configured);

        for (int i = 0; i < hashes.size(); i++) {
            try {
                call(session, "loadCapFile", cap, null, lfdbh(hashes.get(i)));
                return;
            } catch (InvocationTargetException e) {
                boolean lastAttempt = i == hashes.size() - 1;
                String message = String.valueOf(e.getCause().getMessage());
                if (lastAttempt || !message.contains("6A80")) {
                    throw e;
                }
                out.println("#   " + hashes.get(i) + " load file hash rejected, trying "
                        + hashes.get(i + 1));
            }
        }
    }

    // Without this JDK 8 on macOS does not load SunPCSC at all and reports no readers. The
    // framework has been in the dyld cache instead of on disk since macOS 11, so whether the path
    // can be loaded cannot be checked beforehand. Newer JDKs find it themselves.
    private void useMacosPcscLibrary() {
        String property = "sun.security.smartcardio.library";
        if (System.getProperty("os.name", "").toLowerCase().contains("mac")
                && System.getProperty(property) == null) {
            System.setProperty(property, MACOS_PCSC);
        }
    }

    private CardTerminal selectTerminal(String wanted) throws Exception {
        List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
        if (terminals.isEmpty()) {
            throw new IllegalStateException("No card readers found, is the reader connected?");
        }

        List<CardTerminal> candidates = new ArrayList<CardTerminal>();
        for (CardTerminal terminal : terminals) {
            boolean matchesName = wanted.isEmpty()
                    || terminal.getName().toLowerCase().contains(wanted.toLowerCase());
            if (matchesName && terminal.isCardPresent()) {
                candidates.add(terminal);
            }
        }

        if (candidates.isEmpty()) {
            throw new IllegalStateException("No card in the readers "
                    + terminals + (wanted.isEmpty() ? "" : " matching '" + wanted + "'"));
        }
        if (candidates.size() > 1) {
            throw new IllegalStateException("Several readers have a card, select one with"
                    + " -Pdeploy_reader=<name>: " + candidates);
        }

        out.println("# reader: " + candidates.get(0).getName());
        return candidates.get(0);
    }

    // Returns a connection on the first protocol the card answers SELECT on.
    private Card connect(CardTerminal terminal) throws Exception {
        String configured = System.getProperty("deploy.protocol", "auto");
        String[] protocols = "auto".equals(configured)
                ? PROTOCOLS
                : new String[] {configured};

        Exception failure = null;
        for (String protocol : protocols) {
            Card card = null;
            try {
                card = terminal.connect(protocol);
                card.getBasicChannel().transmit(new CommandAPDU(SELECT_ISD));
                return card;
            } catch (Exception e) {
                failure = e;
                if (card != null) {
                    card.disconnect(false);
                }
                out.println("# protocol " + protocol + " unusable: " + e.getMessage());
            }
        }
        throw new IllegalStateException("Card does not answer on any of the protocols "
                + Arrays.toString(protocols), failure);
    }

    private Object aid(String hex) throws Exception {
        return gpClass("pro.javacard.capfile.AID", "pro.javacard.AID")
                .getConstructor(String.class).newInstance(hex);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Object lfdbh(String name) throws Exception {
        return Enum.valueOf((Class<Enum>) gpClass("pro.javacard.gp.GPData$LFDBH"), name);
    }

    // GPSession.discover() takes an APDUBIBO in gp.jar 20.07.04 and a BIBO in current releases.
    private Object biboArgument(Object bibo) throws Exception {
        for (Method method : gpClass("pro.javacard.gp.GPSession").getMethods()) {
            if ("discover".equals(method.getName())
                    && method.getParameterTypes()[0].isInstance(bibo)) {
                return bibo;
            }
        }
        return gpClass("apdu4j.APDUBIBO").getConstructors()[0].newInstance(bibo);
    }

    private static List<String> commaSeparated(String value) {
        List<String> values = new ArrayList<String>();
        for (String part : value.split(",")) {
            if (!part.trim().isEmpty()) {
                values.add(part.trim());
            }
        }
        return values;
    }

    private static Class<?> gpClass(String... names) {
        for (String name : names) {
            try {
                return Class.forName(name);
            } catch (ClassNotFoundException e) {
                continue;
            }
        }
        throw new IllegalStateException("Not found in gp.jar: " + Arrays.toString(names)
                + ". Is the gp.jar release supported?");
    }

    private static Object call(Object target, String name, Object... args) throws Exception {
        return invoke(target.getClass(), target, name, args);
    }

    private static Object callStatic(Class<?> type, String name, Object... args) throws Exception {
        return invoke(type, null, name, args);
    }

    private static Object invoke(Class<?> type, Object target, String name, Object... args)
            throws Exception {
        return findMethod(type, name, args.length).invoke(target, args);
    }

    // Methods are matched by name and argument count, which is unambiguous for the ones used here
    // and tolerates the parameter type changes between gp.jar releases.
    private static Method findMethod(Class<?> type, String name, int arguments) {
        for (Method method : type.getMethods()) {
            if (method.getName().equals(name) && method.getParameterTypes().length == arguments) {
                return method;
            }
        }
        throw new IllegalStateException("No method " + name + "/" + arguments + " in " + type);
    }

    private static String hex(byte[] bytes) {
        StringBuilder hex = new StringBuilder();
        for (byte b : bytes) {
            hex.append(String.format("%02X", b));
        }
        return hex.toString();
    }
}
