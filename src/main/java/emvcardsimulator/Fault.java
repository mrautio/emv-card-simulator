package emvcardsimulator;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Fault injection entry: a trigger and an action. Each applet has a table of TABLE_SIZE entries in its DataStore, set with
 * the SET FAULT setup command ('80 11'). Triggers are evaluated once per command, except GET RESPONSE that keeps the faults of
 * the command whose response it returns, and the actions of the triggered entries apply to that command.
 */
public class Fault {
    public static final short TABLE_SIZE = (short) 8;

    // Kinds of fault actions
    public static final byte KIND_NONE = (byte) 0x00;
    // Value of a tag is mutated, the tag length is encoded for the mutated value: tag || offset || length || strategy || argument
    public static final byte KIND_TAG_VALUE = (byte) 0x01;
    // BER-TLV encoding of a tag is malformed: tag || mode || argument 1 || argument 2
    public static final byte KIND_TAG_ENCODING = (byte) 0x02;
    // Status word of the response is replaced: SW1 SW2 || '00' command is not processed and has no response data,
    // '01' command is processed and its response data is sent
    public static final byte KIND_STATUS_WORD = (byte) 0x03;
    // Response data or its sending in parts with '61xx' and GET RESPONSE is faulted: mode || argument
    public static final byte KIND_RESPONSE_CHAIN = (byte) 0x04;
    // Busy-wait before the command is processed: number of delay units (2)
    public static final byte KIND_DELAY = (byte) 0x05;

    // Trigger modes, n is the trigger argument of 1 - 255
    public static final byte TRIGGER_ALWAYS = (byte) 0x00;
    // Randomly with probability 1/n
    public static final byte TRIGGER_RANDOM = (byte) 0x01;
    // Only on the nth matching command until the fault is reset
    public static final byte TRIGGER_ONCE = (byte) 0x02;
    // On every nth matching command
    public static final byte TRIGGER_EVERY = (byte) 0x03;

    // Tag value mutation strategies
    public static final byte VALUE_RANDOM = (byte) 0x00;
    // XOR with the argument, argument '00' flips one random bit of the range
    public static final byte VALUE_XOR = (byte) 0x01;
    public static final byte VALUE_FILL = (byte) 0x02;
    // Each firing fills the range with the next value of BOUNDARY_VALUES
    public static final byte VALUE_BOUNDARY = (byte) 0x03;
    // Range is a big-endian number increased by the number of firings
    public static final byte VALUE_INCREMENT = (byte) 0x04;

    // Tag encoding modes
    // Length is the value length plus the signed argument 1
    public static final byte ENCODING_LENGTH_DELTA = (byte) 0x01;
    // Long form length of argument 1 (1 - 4) bytes, e.g. '81 05', '82 00 05' or '84 00 00 00 05'
    public static final byte ENCODING_LONG_FORM_LENGTH = (byte) 0x02;
    // Indefinite length '80', argument 1 not '00' appends end-of-contents '00 00'
    public static final byte ENCODING_INDEFINITE_LENGTH = (byte) 0x03;
    // Only the first tag byte, announcing a subsequent tag byte, without length and value
    public static final byte ENCODING_TRUNCATED_TAG = (byte) 0x04;
    // Constructed bit of the tag is set, the value is parsed as data objects
    public static final byte ENCODING_CONSTRUCTED = (byte) 0x05;
    // Argument 1 padding bytes of argument 2 before the data object
    public static final byte ENCODING_PADDING = (byte) 0x06;
    public static final byte ENCODING_OMIT = (byte) 0x07;
    public static final byte ENCODING_DUPLICATE = (byte) 0x08;

    // Response chain modes
    // GET RESPONSE returns the same part with the same '61xx' again, the chain never ends
    public static final byte CHAIN_REPEAT = (byte) 0x01;
    // '61xx' announces argument bytes instead of the remaining length
    public static final byte CHAIN_WRONG_REMAINING = (byte) 0x02;
    // '6Cxx' gives argument as the exact length instead of the response length
    public static final byte CHAIN_WRONG_EXACT_LENGTH = (byte) 0x03;
    // Last argument bytes of the response data are not sent
    public static final byte CHAIN_TRUNCATE = (byte) 0x04;
    // Response data is sent in parts of argument bytes with '61xx' and GET RESPONSE, also with T=1 and contactless
    public static final byte CHAIN_FORCE = (byte) 0x05;

    private static final byte[] BOUNDARY_VALUES = { (byte) 0x00, (byte) 0x01, (byte) 0x7F, (byte) 0x80, (byte) 0xFE, (byte) 0xFF };

    // Kind specific data length of each kind, tag faults have a tag of one to three bytes before it
    private static final byte[] PARAMETERS_LENGTH = { (byte) 0, (byte) 4, (byte) 3, (byte) 3, (byte) 2, (byte) 2 };
    // Kind || INS || interface || trigger mode || n
    private static final short HEADER_LENGTH = (short) 5;
    private static final short TAG_SIZE = (short) 3;

    // Seed of the pseudo-random generator, 0 uses the random generator of the card
    private static short seed = (short) 0;
    // Pseudo-random generator state, restarts from the seed at card reset
    private static short[] randomState;

    private byte kind;
    // INS of the matching commands, '00' matches any command
    private byte ins;
    // Interface of the matching commands, see EmvTag.SCOPE_*
    private byte scope;
    private byte triggerMode;
    private short triggerArgument;
    private short matchCount;
    private short fireCount;
    // Tag of a tag fault in right aligned three byte form
    private byte[] tag;
    private byte[] parameters;

    Fault() {
        tag = new byte[TAG_SIZE];
        parameters = new byte[4];
    }

    /**
     * Allocate the transient state shared by the applets.
     */
    static void init() {
        if (randomState == null) {
            randomState = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
        }
    }

    /**
     * Set the seed of the pseudo-random generator used by the faults, 0 uses the random generator of the card.
     */
    static void setSeed(short value) {
        seed = value;
        randomState[0] = value;
    }

    /**
     * Next state of the 16 bit xorshift pseudo-random generator, the state is not 0.
     */
    private static short xorshift(short x) {
        x ^= (short) (x << 7);
        x ^= (short) ((x >> 9) & 0x007F);
        x ^= (short) (x << 8);
        return x;
    }

    /**
     * Next 16 bit random number of the trigger evaluation, from the seeded generator or the random generator of the card.
     */
    private static short nextRandom() {
        if (seed == (short) 0) {
            EmvApplet.randomData.generateData(EmvApplet.tmpBuffer, (short) 0, (short) 2);
            return Util.getShort(EmvApplet.tmpBuffer, (short) 0);
        }

        short x = randomState[0];
        randomState[0] = xorshift((x == (short) 0) ? seed : x);
        return randomState[0];
    }

    /**
     * Set table entry from SET FAULT command data, empty data clears the entry.
     */
    static void set(DataStore store, short index, byte[] buf, short offset, short length) {
        if (index < (short) 0 || index >= TABLE_SIZE) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        Fault fault = store.faults[index];
        if (length == (short) 0) {
            fault.kind = KIND_NONE;
            store.activeFaults[index] = false;
            return;
        }
        if (length < HEADER_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        final byte newKind = buf[offset];
        final byte newScope = buf[(short) (offset + 2)];
        final byte newTriggerMode = buf[(short) (offset + 3)];
        final short newTriggerArgument = (short) (buf[(short) (offset + 4)] & 0x00FF);
        if (newKind <= KIND_NONE || newKind > KIND_DELAY
            || (newScope != EmvTag.SCOPE_ANY && newScope != EmvTag.SCOPE_CONTACT && newScope != EmvTag.SCOPE_CONTACTLESS)
            || newTriggerMode < TRIGGER_ALWAYS || newTriggerMode > TRIGGER_EVERY
            || (newTriggerMode != TRIGGER_ALWAYS && newTriggerArgument == (short) 0)) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        short parametersOffset = (short) (offset + HEADER_LENGTH);
        short tagLength = (short) 0;
        if (newKind == KIND_TAG_VALUE || newKind == KIND_TAG_ENCODING) {
            if (length == HEADER_LENGTH || buf[parametersOffset] == (byte) 0x00) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
            tagLength = EmvTag.tagEntryLength(buf, parametersOffset);
        }
        if (length != (short) (HEADER_LENGTH + tagLength + PARAMETERS_LENGTH[newKind])) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        checkParameters(newKind, buf, (short) (parametersOffset + tagLength));

        // Entry is disabled until set completely
        fault.kind = KIND_NONE;
        store.activeFaults[index] = false;
        fault.ins = buf[(short) (offset + 1)];
        fault.scope = newScope;
        fault.triggerMode = newTriggerMode;
        fault.triggerArgument = newTriggerArgument;
        fault.matchCount = (short) 0;
        fault.fireCount = (short) 0;
        Util.arrayFillNonAtomic(fault.tag, (short) 0, TAG_SIZE, (byte) 0x00);
        Util.arrayCopy(buf, parametersOffset, fault.tag, (short) (TAG_SIZE - tagLength), tagLength);
        Util.arrayFillNonAtomic(fault.parameters, (short) 0, (short) fault.parameters.length, (byte) 0x00);
        Util.arrayCopy(buf, (short) (parametersOffset + tagLength), fault.parameters, (short) 0, PARAMETERS_LENGTH[newKind]);
        fault.kind = newKind;
    }

    private static void checkParameters(byte kind, byte[] buf, short offset) {
        final byte mode = buf[offset];
        final byte argument = buf[(short) (offset + 1)];
        boolean valid = true;
        switch (kind) {
            case KIND_TAG_VALUE:
                valid = buf[(short) (offset + 2)] >= VALUE_RANDOM && buf[(short) (offset + 2)] <= VALUE_INCREMENT;
                break;
            case KIND_TAG_ENCODING:
                valid = mode >= ENCODING_LENGTH_DELTA && mode <= ENCODING_DUPLICATE
                    && (mode != ENCODING_LONG_FORM_LENGTH || (argument >= (byte) 1 && argument <= (byte) 4));
                break;
            case KIND_RESPONSE_CHAIN:
                valid = mode >= CHAIN_REPEAT && mode <= CHAIN_FORCE && (mode != CHAIN_FORCE || argument != (byte) 0x00);
                break;
            default:
                break;
        }

        if (!valid) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }
    }

    /**
     * Clear all faults of the table.
     */
    static void clear(DataStore store) {
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            store.faults[i].kind = KIND_NONE;
            store.activeFaults[i] = false;
        }
        randomState[0] = seed;
    }

    /**
     * Evaluate the triggers of the current applet's faults for a command, the triggered faults apply to the command.
     */
    static void evaluate(byte commandIns, boolean contactless) {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            store.activeFaults[i] = false;
            if (fault.kind == KIND_NONE || (fault.ins != (byte) 0x00 && fault.ins != commandIns)
                || (fault.scope == EmvTag.SCOPE_CONTACT && contactless) || (fault.scope == EmvTag.SCOPE_CONTACTLESS && !contactless)) {
                continue;
            }

            boolean fire;
            switch (fault.triggerMode) {
                case TRIGGER_RANDOM:
                    fire = (short) ((nextRandom() & 0x7FFF) % fault.triggerArgument) == (short) 0;
                    break;
                case TRIGGER_ONCE:
                    if (fault.matchCount < fault.triggerArgument) {
                        fault.matchCount++;
                    }
                    fire = fault.matchCount == fault.triggerArgument && fault.fireCount == (short) 0;
                    break;
                case TRIGGER_EVERY:
                    fault.matchCount++;
                    if (fault.matchCount == fault.triggerArgument) {
                        fault.matchCount = (short) 0;
                    }
                    fire = fault.matchCount == (short) 0;
                    break;
                default:
                    fire = true;
                    break;
            }

            if (fire) {
                store.activeFaults[i] = true;
                if (fault.fireCount != (short) 0x7FFF) {
                    fault.fireCount++;
                }
                // Same mutation for each serialization of the tag in the command, e.g. response data and its CDA hash
                short nonce = nextRandom();
                store.faultNonces[i] = (nonce == (short) 0) ? (short) 1 : nonce;
            }
        }
    }

    /**
     * Active fault of the kind, null if none.
     */
    static Fault findActive(byte kind) {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            if (store.activeFaults[i] && store.faults[i].kind == kind) {
                return store.faults[i];
            }
        }
        return null;
    }

    /**
     * Active fault of the kind for the tag in right aligned three byte form, null if none.
     */
    static Fault findActive(byte kind, byte[] tagId) {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            if (store.activeFaults[i] && fault.kind == kind && Util.arrayCompare(fault.tag, (short) 0, tagId, (short) 0, TAG_SIZE) == 0) {
                return fault;
            }
        }
        return null;
    }

    /**
     * Active response chain fault of the mode, null if none.
     */
    static Fault findActiveChain(byte mode) {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            if (store.activeFaults[i] && fault.kind == KIND_RESPONSE_CHAIN && fault.parameters[0] == mode) {
                return fault;
            }
        }
        return null;
    }

    /**
     * True if the tag has an active value or encoding fault.
     */
    static boolean isTagFaulted(byte[] tagId) {
        return findActive(KIND_TAG_VALUE, tagId) != null || findActive(KIND_TAG_ENCODING, tagId) != null;
    }

    /**
     * First kind specific parameter, e.g. encoding or response chain mode.
     */
    byte getMode() {
        return parameters[0];
    }

    /**
     * Kind specific parameter at the index.
     */
    byte getParameter(short index) {
        return parameters[index];
    }

    /**
     * Status word of a status word fault.
     */
    short getStatusWord() {
        return Util.getShort(parameters, (short) 0);
    }

    /**
     * True if the command of a status word fault is processed and its response data is sent.
     */
    boolean isResponseDataKept() {
        return parameters[2] != (byte) 0x00;
    }

    /**
     * Busy-wait the delay units of the active delay faults. A unit is filling a 255 byte buffer, its duration depends on the card.
     */
    static void delay() {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            if (!store.activeFaults[i] || fault.kind != KIND_DELAY) {
                continue;
            }

            // Unsigned count of units
            for (short units = Util.getShort(fault.parameters, (short) 0); units != (short) 0; units--) {
                Util.arrayFillNonAtomic(EmvApplet.tmpBuffer, (short) 0, (short) EmvApplet.tmpBuffer.length, (byte) units);
            }
        }
    }

    /**
     * Value length of the tag after the mutations of its active value faults, at most 255 bytes.
     */
    static short mutatedLength(byte[] tagId, short valueLength) {
        DataStore store = DataStore.current;
        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            if (!store.activeFaults[i] || fault.kind != KIND_TAG_VALUE
                || Util.arrayCompare(fault.tag, (short) 0, tagId, (short) 0, TAG_SIZE) != 0) {
                continue;
            }

            short end = fault.rangeEnd();
            if (end > valueLength) {
                valueLength = end;
            }
        }
        return valueLength;
    }

    /**
     * End of the mutated range in the value, at most 255.
     */
    private short rangeEnd() {
        short end = (short) ((parameters[0] & 0x00FF) + (parameters[1] & 0x00FF));
        return (end > (short) 0x00FF) ? (short) 0x00FF : end;
    }

    /**
     * Apply the active value faults of the tag to its value in dst. The value of valueLength bytes is extended to
     * mutatedLength bytes with zeros before the mutations. Bytes beyond dst are not written.
     */
    static void mutate(byte[] tagId, byte[] dst, short valueOffset, short valueLength) {
        DataStore store = DataStore.current;
        final short limit = (short) dst.length;
        short mutatedLength = mutatedLength(tagId, valueLength);
        fill(dst, (short) (valueOffset + valueLength), (short) (mutatedLength - valueLength), (byte) 0x00);

        for (short i = (short) 0; i < TABLE_SIZE; i++) {
            Fault fault = store.faults[i];
            if (!store.activeFaults[i] || fault.kind != KIND_TAG_VALUE
                || Util.arrayCompare(fault.tag, (short) 0, tagId, (short) 0, TAG_SIZE) != 0) {
                continue;
            }

            short start = (short) (valueOffset + (fault.parameters[0] & 0x00FF));
            short end = (short) (valueOffset + fault.rangeEnd());
            if (end > limit) {
                end = limit;
            }
            if (start >= end) {
                continue;
            }

            fault.mutateRange(store.faultNonces, i, dst, start, end);
        }
    }

    private void mutateRange(short[] nonces, short index, byte[] dst, short start, short end) {
        final byte argument = parameters[3];
        switch (parameters[2]) {
            case VALUE_XOR:
                if (argument == (byte) 0x00) {
                    short bit = (short) ((xorshift(nonces[index]) & 0x7FFF) % (short) (8 * (end - start)));
                    short position = (short) (start + (short) (bit >> 3));
                    dst[position] ^= (byte) (1 << (bit & 0x07));
                    break;
                }
                for (short i = start; i < end; i++) {
                    dst[i] ^= argument;
                }
                break;
            case VALUE_FILL:
                fill(dst, start, (short) (end - start), argument);
                break;
            case VALUE_BOUNDARY:
                fill(dst, start, (short) (end - start), BOUNDARY_VALUES[(short) ((short) (fireCount - 1) % (short) BOUNDARY_VALUES.length)]);
                break;
            case VALUE_INCREMENT:
                short carry = fireCount;
                for (short i = (short) (end - 1); i >= start && carry != (short) 0; i--) {
                    short sum = (short) ((dst[i] & 0x00FF) + (carry & 0x00FF));
                    dst[i] = (byte) sum;
                    carry = (short) (((carry >> 8) & 0x00FF) + ((sum >> 8) & 0x00FF));
                }
                break;
            default:
                // Random bytes from the nonce of the command, the same for each serialization in the command
                short state = nonces[index];
                for (short i = start; i < end; i++) {
                    state = xorshift(state);
                    dst[i] = (byte) state;
                }
                break;
        }
    }

    /**
     * Fill bytes of dst, bytes beyond dst are not written.
     */
    static void fill(byte[] dst, short offset, short length, byte value) {
        short available = (short) (dst.length - offset);
        if (length > available) {
            length = available;
        }
        if (length > (short) 0) {
            Util.arrayFillNonAtomic(dst, offset, length, value);
        }
    }
}
