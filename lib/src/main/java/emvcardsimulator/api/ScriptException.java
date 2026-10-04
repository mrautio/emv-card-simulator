package emvcardsimulator.api;

/**
 * APDU script could not be parsed or the card did not respond as the script expected.
 */
public class ScriptException extends Exception {
    private static final long serialVersionUID = 1L;

    public ScriptException(String message) {
        super(message);
    }
}
