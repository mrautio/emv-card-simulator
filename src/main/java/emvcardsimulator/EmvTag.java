package emvcardsimulator;

import javacard.framework.Util;

public class EmvTag {

    protected EmvTag next;
    protected EmvTag previous;
    private static EmvTag head = null;
    private static EmvTag tail = null;

    private byte[] tag;
    private byte[] data;
    private byte   length;

    protected EmvTag(short tagId, byte[] src, short srcOffset, byte length) {
        tag = new byte[2];
        data = new byte[255];
        this.length = length;

        Util.setShort(tag, (short) 0, tagId);
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
     * Add or update BER-TLV EMV tag to memory.
     */
    public static EmvTag setTag(short tagId, byte[] src, short srcOffset, byte length) {
        EmvTag tag = EmvTag.findTag(tagId);
        if (tag == null) {
            tag = new EmvTag(tagId, src, srcOffset, length);
        } else {
            tag.setData(src, srcOffset, length);
        }

        return tag;
    }

    /**
     * Find BER-TLV EMV tag.
     */
    public static EmvTag findTag(short tag) {
        for (EmvTag iter = EmvTag.head; iter != null; iter = iter.next) {
            short iterTag = Util.getShort(iter.tag, (short) 0);
            if (tag == iterTag) {
                return iter;
            }
        }

        return null;
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

        if (tag[0] == (byte) 0x00) {
            Util.arrayCopy(tag, (short) 1, dst, dstOffset, (short) 1);
            copyOffset += 1;
        } else {
            Util.arrayCopy(tag, (short) 0, dst, dstOffset, (short) 2);
            copyOffset += 2;
        }

        short shortLength = (short) (length & 0x00FF);
        if (shortLength < 128) {
            dst[copyOffset] = length;
            copyOffset += 1;
        } else {
            dst[copyOffset] = (byte) 0x81;
            copyOffset += 1;
            dst[copyOffset] = length;
            copyOffset += 1;
        }

        copyOffset = copyDataToArray(dst, copyOffset);

        return copyOffset;
    }

    /**
     * Serialize tag's data to array, i.e. no BER-TLV header.
     */
    public short copyDataToArray(byte[] dst, short dstOffset) {
        short shortLength = (short) (length & 0x00FF);

        Util.arrayCopy(data, (short) 0, dst, dstOffset, shortLength);

        return (short) (dstOffset + shortLength);
    }
}
