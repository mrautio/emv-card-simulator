package emvcardsimulator.api;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * APDU script in the cardtool YAML format, i.e. a list of {@code req} command and {@code res} status word hex strings.
 * An optional {@code card_information} entry describes the card and is not sent to the card:
 * <pre>
 * - card_information:
 *     title: 'Test card'
 * - req: '00 A4 04 00 07 AF FF FF FF FF 12 34'
 *   res: '90 00'
 * </pre>
 */
public final class ApduScript {

    /**
     * Scripts bundled from src/main/rust/config, and with "test/" prefix from src/test/java/config.
     */
    public static final List<String> BUNDLED = Collections.unmodifiableList(Arrays.asList(
        "card_setup_pse_apdus.yaml",
        "card_setup_ppse_apdus.yaml",
        "card_setup_app_apdus.yaml",
        "card_setup_app_apdus-spankki.yaml",
        "card_setup_ppse_apdus-spankki.yaml",
        "setup_fuzzing_apdus.yaml",
        "download_log_pse_apdus.yaml",
        "test/card_setup_pse_apdus.yaml",
        "test/card_setup_ppse_apdus.yaml",
        "test/card_setup_app_apdus.yaml",
        "test/card_setup_app_visa_contactless_apdus.yaml",
        "test/card_setup_ppse_mastercard_apdus.yaml",
        "test/card_setup_app_mastercard_contactless_apdus.yaml",
        "test/card_setup_ppse_mockstercard_apdus.yaml",
        "test/card_setup_app_mockstercard_contactless_apdus.yaml",
        "test/card_log_consume_apdus.yaml"
    ));

    private static final Pattern ENTRY = Pattern.compile("^\\s*(-\\s*)?(\\w+)\\s*:\\s*(.*?)\\s*$");

    private static final String CARD_INFORMATION = "card_information";

    private static final short CMD_SET_EMV_TAG = (short) 0x8001;

    /**
     * Command APDU and the expected response status word.
     */
    public static final class Command {
        public final byte[] request;
        public final byte[] response;

        Command(byte[] request, byte[] response) {
            this.request = request;
            this.response = response;
        }
    }

    private final List<Command> commands;
    private final Map<String, String> cardInformation;

    private ApduScript(List<Command> commands, Map<String, String> cardInformation) {
        this.commands = Collections.unmodifiableList(commands);
        this.cardInformation = Collections.unmodifiableMap(cardInformation);
    }

    public List<Command> commands() {
        return commands;
    }

    /**
     * Values of the card_information entry, e.g. {@code title}. With several entries the first value of a key is kept.
     */
    public Map<String, String> cardInformation() {
        return cardInformation;
    }

    /**
     * Parse script from YAML text.
     */
    public static ApduScript parse(String yaml) throws ScriptException {
        List<Command> commands = new ArrayList<>();
        Map<String, String> cardInformation = new LinkedHashMap<>();
        byte[] request = null;
        byte[] response = null;
        boolean inCardInformation = false;
        String[] lines = yaml.split("\r?\n", -1);

        for (int i = 0; i < lines.length; i++) {
            String line = stripComment(lines[i]);
            if (line.trim().isEmpty()) {
                continue;
            }

            Matcher entry = ENTRY.matcher(line);
            if (!entry.matches()) {
                throw new ScriptException("Line " + (i + 1) + ": unsupported syntax: " + lines[i].trim());
            }

            String key = entry.group(2);
            String value = unquote(entry.group(3));
            if (entry.group(1) != null) {
                if (request != null || response != null) {
                    commands.add(command(request, response, i));
                }
                request = null;
                response = null;
                inCardInformation = CARD_INFORMATION.equals(key) && value.isEmpty();
                if (inCardInformation) {
                    continue;
                }
            } else if (inCardInformation) {
                if (!cardInformation.containsKey(key)) {
                    cardInformation.put(key, value);
                }
                continue;
            }

            if ("req".equals(key)) {
                request = decodeHex(value, i);
            } else if ("res".equals(key)) {
                response = decodeHex(value, i);
            } else {
                throw new ScriptException("Line " + (i + 1) + ": unsupported key: " + key);
            }
        }

        if (request != null || response != null) {
            commands.add(command(request, response, lines.length));
        }

        return new ApduScript(commands, cardInformation);
    }

    /**
     * Load a script from {@link #BUNDLED}.
     */
    public static ApduScript bundled(String name) throws IOException, ScriptException {
        if (!BUNDLED.contains(name)) {
            throw new IOException("Not a bundled script: " + name);
        }

        try (InputStream in = ApduScript.class.getResourceAsStream("/emvcardsimulator/scripts/" + name)) {
            if (in == null) {
                throw new IOException("Missing bundled script: " + name);
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            for (int n; (n = in.read(buffer)) > 0; ) {
                out.write(buffer, 0, n);
            }

            return parse(new String(out.toByteArray(), StandardCharsets.UTF_8));
        }
    }

    /**
     * EMV tag values personalized by the script's SET EMV TAG commands, keyed by tag.
     */
    public Map<Integer, byte[]> emvTags() {
        Map<Integer, byte[]> tags = new LinkedHashMap<>();
        for (Command command : commands) {
            byte[] req = command.request;
            if (req.length >= 5 && (short) ((req[0] << 8) | (req[1] & 0xFF)) == CMD_SET_EMV_TAG) {
                int length = Math.min(req[4] & 0xFF, req.length - 5);
                tags.put(((req[2] & 0xFF) << 8) | (req[3] & 0xFF), Arrays.copyOfRange(req, 5, 5 + length));
            }
        }

        return tags;
    }

    private static Command command(byte[] request, byte[] response, int line) throws ScriptException {
        if (request == null || response == null) {
            throw new ScriptException("Line " + line + ": entry needs both req and res");
        }

        return new Command(request, response);
    }

    private static String stripComment(String line) {
        char quote = 0;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (quote != 0) {
                quote = (c == quote) ? 0 : quote;
            } else if (c == '\'' || c == '"') {
                quote = c;
            } else if (c == '#' && (i == 0 || Character.isWhitespace(line.charAt(i - 1)))) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    private static String unquote(String value) {
        if (value.length() >= 2 && value.charAt(0) == '\'' && value.endsWith("'")) {
            return value.substring(1, value.length() - 1).replace("''", "'");
        }
        if (value.length() >= 2 && value.charAt(0) == '"' && value.endsWith("\"")) {
            return value.substring(1, value.length() - 1);
        }
        return value;
    }

    private static byte[] decodeHex(String hex, int line) throws ScriptException {
        String digits = hex.replaceAll("\\s", "");
        if (!digits.matches("([0-9A-Fa-f]{2})*")) {
            throw new ScriptException("Line " + (line + 1) + ": not hex bytes: " + hex);
        }

        byte[] result = new byte[digits.length() / 2];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) Integer.parseInt(digits.substring(i * 2, i * 2 + 2), 16);
        }

        return result;
    }
}
