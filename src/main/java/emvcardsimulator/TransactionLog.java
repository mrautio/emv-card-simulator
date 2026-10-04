package emvcardsimulator;

import javacard.framework.Util;

/**
 * Transaction log records (EMV Book 3, Annex D). The Log Entry (tag 9F4D) gives the SFI and the maximum number of records,
 * and the Log Format (tag 9F4F) the data elements of a record. Record 1 is the most recent transaction.
 * Records are concatenated values of the data elements without TLV coding.
 */
public class TransactionLog {

    private byte[] records = null;
    private short recordLength = 0;
    private byte maxRecords = 0;
    private byte count = 0;
    private byte newest = 0;

    /**
     * Remove all records.
     */
    public void clear() {
        count = (byte) 0;
        newest = (byte) 0;
    }

    /**
     * Add a record as the most recent one, the oldest record is overwritten when the log is full.
     * Log is cleared when the record length or the maximum number of records changes.
     */
    public void append(byte[] src, short srcOffset, short length, byte maximumRecords) {
        if (maximumRecords <= (byte) 0 || length <= (short) 0) {
            return;
        }

        if (records == null || recordLength != length || maxRecords != maximumRecords) {
            records = null;
            records = new byte[(short) (length * maximumRecords)];
            recordLength = length;
            maxRecords = maximumRecords;
            clear();
        }

        newest = (byte) ((short) (newest + 1) % maxRecords);
        Util.arrayCopy(src, srcOffset, records, (short) (newest * recordLength), recordLength);
        if (count < maxRecords) {
            count++;
        }
    }

    /**
     * Replace the most recent record, e.g. when the second GENERATE AC completes the transaction.
     */
    public void replaceNewest(byte[] src, short srcOffset, short length) {
        if (count == (byte) 0 || length != recordLength) {
            return;
        }

        Util.arrayCopy(src, srcOffset, records, (short) (newest * recordLength), recordLength);
    }

    /**
     * Copy record to destination, record number 1 is the most recent. Returns the record length, or -1 if the record does not exist.
     */
    public short read(byte recordNumber, byte[] dst, short dstOffset) {
        if (recordNumber < (byte) 1 || recordNumber > count) {
            return (short) -1;
        }

        short index = (short) ((short) (newest - recordNumber + 1 + maxRecords) % maxRecords);
        Util.arrayCopyNonAtomic(records, (short) (index * recordLength), dst, dstOffset, recordLength);

        return recordLength;
    }
}
