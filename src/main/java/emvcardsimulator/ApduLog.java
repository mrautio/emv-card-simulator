package emvcardsimulator;

import javacard.framework.JCSystem;
import javacard.framework.Util;

public class ApduLog {

    public ApduLog next;
    protected ApduLog previous;
    public static ApduLog head = null;
    public static ApduLog tail = null;

    private byte[] data;
    private byte   length;

    public static short maxCount = 10;
    public static short count = 0;

    protected ApduLog(byte[] src, short srcOffset, byte length) {
        data = new byte[(short) (length & 0x00FF)];
        this.length = length;

        setData(src, srcOffset, this.length);

        next = null;
        previous = tail;
        if (previous != null) {
            previous.next = this;
        }

        if (head == null) {
            head = this;
        }
        tail = this;
    }

    /**
     * Add APDU log entry.
     */
    public static void addLogEntry(short responseTrailer) {
        Util.setShort(EmvApplet.tmpBuffer, (short) 0, responseTrailer);
        addLogEntry(EmvApplet.tmpBuffer, (short) 0, (byte) 0x02);
    }

    /**
     * Add APDU log entry.
     */
    public static void addLogEntry(byte[] src, short srcOffset, byte length) {
        if (maxCount == (short) 0) {
            return;
        }

        if (src[srcOffset] == (byte) 0xE0) {
            // do not log internal commands
            return;
        }

        new ApduLog(src, srcOffset, length);
        count += (short) 1;
        if (count > maxCount) {
            ApduLog.removeLog(head);
        }
    }

    /**
     * Remove all stored logs.
     */
    public static short clear() {
        short count = (short) 0;

        for (ApduLog iter = ApduLog.head; iter != null; ) {
            ApduLog removeEntry = iter;
            iter = iter.next;

            if (removeLog(removeEntry)) {
                count++;
            }
        }    

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Remove log entry.
     */
    public static boolean removeLog(ApduLog logEntry) {
        if (logEntry == null) {
            return false;
        }

        ApduLog previousLogEntry = logEntry.previous;
        ApduLog nextLogEntry = logEntry.next;

        JCSystem.beginTransaction();

        if (head == logEntry) {
            head = nextLogEntry;
        }
        if (tail == logEntry) {
            tail = previousLogEntry;
        }
        if (previousLogEntry != null) {
            previousLogEntry.next = nextLogEntry;
        }
        if (nextLogEntry != null) {
            nextLogEntry.previous = previousLogEntry;
        }

        count -= (short) 1;

        JCSystem.commitTransaction();

        return true;
    }

    /**
     * Set the data/value and length of the tag.
     */
    public void setData(byte[] src, short srcOffset, byte length) {
        this.length = length;
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));
    }

    /**
     * Return first ApduLog instance.
     */
    public static ApduLog getHead() {
        return ApduLog.head;
    }

    /**
     * Return next ApduLog instance.
     */
    public ApduLog getNext() {
        return next;
    }

    /**
     * Get tag data/value.
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Get data length.
     */
    public byte getLength() {
        return length;
    }

    /**
     * Copy log data to array.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        return (short) (dstOffset + shortLength);
    }
}
