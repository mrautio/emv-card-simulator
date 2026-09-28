package emvcardsimulator;

import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

public class EmvTag {

    protected EmvTag next;
    protected EmvTag previous;
    private static EmvTag head = null;
    private static EmvTag tail = null;

    // Scratch for tag identifiers in right aligned three byte form
    private static byte[] tagIdBuffer = { (byte) 0x00, (byte) 0x00, (byte) 0x00 };

    private byte[] tag;
    private byte[] data;
    private byte   length;

    public byte fuzzOffset      = (byte) 0x00;
    public byte fuzzLength      = (byte) 0x00;
    public byte fuzzFlags       = (byte) 0x00;
    public byte fuzzOccurrence  = (byte) 0x00;

    // Tag is stored right aligned in three bytes, e.g. '00 00 82', '00 9F 36' or 'DF 81 01'
    private static final short TAG_SIZE = (short) 3;

    protected EmvTag(byte[] normalizedTag, byte[] src, short srcOffset, byte length) {
        tag = new byte[TAG_SIZE];
        data = new byte[255];
        this.length = length;

        Util.arrayCopy(normalizedTag, (short) 0, tag, (short) 0, TAG_SIZE);
        if (this.length != 0) {
            setData(src, srcOffset, this.length);
        }

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
     * Length of a tag entry in a tag list: BER-TLV tag of one to three bytes, or '00' followed by a one byte tag.
     */
    public static short tagEntryLength(byte[] buf, short offset) {
        if (buf[offset] == (byte) 0x00) {
            return (short) 2;
        }

        if ((buf[offset] & (byte) 0x1F) != (byte) 0x1F) {
            return (short) 1;
        }

        short length = (short) 2;
        while ((buf[(short) (offset + length - 1)] & (byte) 0x80) != 0) {
            length++;
            if (length > TAG_SIZE) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }

        return length;
    }

    /**
     * Copy tag entry to right aligned three byte form.
     */
    private static void normalizeTag(byte[] buf, short offset, byte[] dst) {
        short length = tagEntryLength(buf, offset);
        Util.arrayFillNonAtomic(dst, (short) 0, TAG_SIZE, (byte) 0x00);
        Util.arrayCopyNonAtomic(buf, offset, dst, (short) (TAG_SIZE - length), length);
    }

    /**
     * True if tag entry equals this tag.
     */
    private boolean matches(byte[] buf, short offset) {
        short length = tagEntryLength(buf, offset);
        for (short i = (short) 0; i < (short) (TAG_SIZE - length); i++) {
            if (tag[i] != (byte) 0x00) {
                return false;
            }
        }
        return Util.arrayCompare(buf, offset, tag, (short) (TAG_SIZE - length), length) == (byte) 0x00;
    }

    /**
     * Add or update BER-TLV EMV tag to memory.
     */
    public static EmvTag setTag(short tagId, byte[] src, short srcOffset, byte length) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            tagIdBuffer[0] = (byte) 0x00;
            Util.setShort(tagIdBuffer, (short) 1, tagId);
            tag = new EmvTag(tagIdBuffer, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Add or update BER-TLV EMV tag to memory, tag is given as a tag entry, see tagEntryLength.
     */
    public static EmvTag setTag(byte[] tagBuf, short tagOffset, byte[] src, short srcOffset, byte length) {
        EmvTag tag = EmvTag.findTag(tagBuf, tagOffset);
        if (tag == null) {
            normalizeTag(tagBuf, tagOffset, tagIdBuffer);
            tag = new EmvTag(tagIdBuffer, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Find BER-TLV EMV tag of one or two bytes.
     */
    public static EmvTag findTag(short tag) {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {
            if (iter.tag[0] == (byte) 0x00 && Util.getShort(iter.tag, (short) 1) == tag) {
                return iter;
            }
        }

        return null;
    }

    /**
     * Find BER-TLV EMV tag given as a tag entry, see tagEntryLength.
     */
    public static EmvTag findTag(byte[] buf, short offset) {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {
            if (iter.matches(buf, offset)) {
                return iter;
            }
        }

        return null;
    }

    /**
     * Remove all stored tags.
     */
    public static short clear() {
        short count = (short) 0;

        for (EmvTag iter = EmvTag.head; iter != null; ) {
            EmvTag removed = iter;

            iter = iter.next;

            removeTag(removed);
            count++;
        }

        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }

        return count;
    }

    /**
     * Clear all fuzz settings.
     */
    public static void clearFuzz() {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {            
            iter.fuzzOffset      = (byte) 0x00;
            iter.fuzzLength      = (byte) 0x00;
            iter.fuzzFlags       = (byte) 0x00;
            iter.fuzzOccurrence  = (byte) 0x00;
        }
    }

    /**
     * Remove tag.
     */
    public static boolean removeTag(short tagId) {
        EmvTag tag = findTag(tagId);
        if (tag == null) {
            return false;
        }

        removeTag(tag);

        return true;
    }

    private static void removeTag(EmvTag tag) {
        EmvTag previousTag = tag.previous;
        EmvTag nextTag = tag.next;

        JCSystem.beginTransaction();

        if (head == tag) {
            head = nextTag;
        }
        if (tail == tag) {
            tail = previousTag;
        }
        if (previousTag != null) {
            previousTag.next = nextTag;
        }
        if (nextTag != null) {
            nextTag.previous = previousTag;
        }

        JCSystem.commitTransaction();
    }

    /**
     * Set the data/value and length of the tag.
     */
    public void setData(byte[] src, short srcOffset, byte length) {
        this.length = length;
        Util.arrayCopy(src, srcOffset, data, (short) 0, (short) (this.length & 0x00FF));
    }

    /**
     * Return first EmvTag instance.
     */
    public static EmvTag getHead() {
        return EmvTag.head;
    }

    /**
     * Return next EmvTag instance.
     */
    public EmvTag getNext() {
        return next;
    }

    /**
     * Get tag name.
     */
    public byte[] getTag() {
        return tag;
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
     * Serialize tag as BER-TLV to array.
     */
    public short copyToArray(byte[] dst, short dstOffset) {
        short copyOffset = dstOffset;

        copyOffset = copyTagToArray(dst, copyOffset);

        short shortLength = (short) (length & 0x00FF);
        if (shortLength >= 128) {
            dst[copyOffset] = (byte) 0x81;
            copyOffset += (short) 1;
        }

        short lengthOffset = copyOffset;
        copyOffset += (short) 1;
        copyOffset = copyDataToArray(dst, copyOffset);

        dst[lengthOffset] = length;

        // re-write tag length with fuzz overflow?
        if (fuzzLength > 0x00 && (fuzzFlags & (1 << 0)) == 1) {
            // TODO: How to handle the case that tag length would need to be represented as two bytes instead of one?
            dst[lengthOffset] = (byte) (copyOffset - lengthOffset - 1);
        }



        return copyOffset;
    }

    /**
     * Serialize tag without leading zero bytes to array.
     */
    public short copyTagToArray(byte[] dst, short dstOffset) {
        short tagOffset = (short) 0;
        while (tagOffset < (short) (TAG_SIZE - 1) && tag[tagOffset] == (byte) 0x00) {
            tagOffset++;
        }

        return Util.arrayCopyNonAtomic(tag, tagOffset, dst, dstOffset, (short) (TAG_SIZE - tagOffset));
    }

    /**
     * Serialize tag's data to array, i.e. no BER-TLV header.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        if (fuzzLength > (byte) 0x00) {
            byte doFuzzing = (byte) 0x00;

            if (fuzzOccurrence > (byte) 0x00) {
                EmvApplet.randomData.generateData(EmvApplet.tmpBuffer, (short) 0, (short) 1);
                doFuzzing = (byte) (EmvApplet.tmpBuffer[(short) 0] % fuzzOccurrence);
            }

            if (doFuzzing == (byte) 0x00) {
                EmvApplet.randomData.generateData(dst, (short) (dstOffset + (fuzzOffset & 0x00FF)), (short) (fuzzLength & 0x00FF));

                if (fuzzLength + fuzzOffset > shortLength) {
                    shortLength = (short) ((fuzzLength & 0x00FF) + (fuzzOffset & 0x00FF));
                }
            }
        }

        return (short) (dstOffset + shortLength);
    }
}
