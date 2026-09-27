package com.otilm.core.key.normalization;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A strict reader of a Java object serialization stream, which never deserializes it: no class is loaded and no object
 * made. The stream's grammar is walked and each class description checked against the one shape expected where it
 * stands, and anything else is refused as unreadable.
 *
 * <p>
 * Only the elements the JDK writes for the secret keys it seals are read: the stream header, new objects, class
 * descriptions of serializable classes and enums, null, the end of a class's annotations, strings, byte arrays, enum
 * constants, and references to the strings and class descriptions read before.
 * </p>
 */
final class JavaSerialization {

    static final byte SC_SERIALIZABLE = 0x02;

    static final byte SC_SERIALIZABLE_ENUM = 0x12;

    private static final byte[] STREAM_HEADER = {(byte) 0xAC, (byte) 0xED, 0x00, 0x05};

    private static final int TC_NULL = 0x70;

    private static final int TC_REFERENCE = 0x71;

    private static final int TC_CLASSDESC = 0x72;

    private static final int TC_OBJECT = 0x73;

    private static final int TC_STRING = 0x74;

    private static final int TC_ARRAY = 0x75;

    private static final int TC_ENDBLOCKDATA = 0x78;

    private static final int TC_ENUM = 0x7E;

    /** The handle a stream gives the first thing it assigns one to; the others follow in order. */
    private static final int BASE_WIRE_HANDLE = 0x7E0000;

    /** {@code byte[]}, with the serialVersionUID the JDK computes for it. */
    private static final StreamClass BYTE_ARRAY = new StreamClass("[B", -5984413125824719648L, SC_SERIALIZABLE,
            List.of(), null);

    /** What a handle stands for when nothing may refer to it: an object, an array or an enum constant. */
    private static final Object NOT_REFERABLE = new Object();

    private final byte[] data;

    private final ByteBuffer numbers;

    private int position;

    /** What each handle stands for, in the order the stream assigns them. */
    private final List<Object> handles = new ArrayList<>();

    private JavaSerialization(byte[] data, int position) {
        this.data = data;
        this.numbers = ByteBuffer.wrap(data);
        this.position = position;
    }

    /**
     * Whether the bytes start with the header of a serialization stream.
     *
     * @param data the bytes
     * @return whether they start with the stream magic and version
     */
    static boolean startsStream(byte[] data) {
        return data.length >= STREAM_HEADER.length
                && Arrays.equals(data, 0, STREAM_HEADER.length, STREAM_HEADER, 0, STREAM_HEADER.length);
    }

    /**
     * A reader of the stream that starts at the offset, placed after its header.
     *
     * @param data the bytes that hold the stream
     * @param offset where the stream starts
     * @return the reader
     */
    static JavaSerialization at(byte[] data, int offset) {
        if (offset < 0 || offset > data.length - STREAM_HEADER.length || !Arrays
                .equals(data, offset, offset + STREAM_HEADER.length, STREAM_HEADER, 0, STREAM_HEADER.length)) {
            throw KeyFileRefusal.unreadableKey();
        }
        return new JavaSerialization(data, offset + STREAM_HEADER.length);
    }

    /**
     * Where the reader stands.
     *
     * @return the offset of the next byte to read
     */
    int position() {
        return position;
    }

    /**
     * Reads a new object of one of the classes; the values of its fields follow, those of its superclass first.
     *
     * @param classes the classes the object may be of
     * @return the class it is of
     */
    StreamClass object(StreamClass... classes) {
        expect(TC_OBJECT);
        StreamClass read = classDescription(classes);
        handles.add(NOT_REFERABLE);
        return read;
    }

    /**
     * Reads a string: a new one, or a reference to one read before.
     *
     * @return the string
     */
    String string() {
        int code = next();
        if (code == TC_REFERENCE) {
            return referenced(String.class);
        }
        if (code != TC_STRING) {
            throw KeyFileRefusal.unreadableKey();
        }
        String value = utf();
        handles.add(value);
        return value;
    }

    /**
     * Reads a string that must be the one given.
     *
     * @param expected the string the stream must hold here
     */
    void string(String expected) {
        if (!expected.equals(string())) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * Reads a new byte array, whose content is left where it stands so that nothing is copied before the stream is
     * known to be one the reader takes.
     *
     * @return where the array's content is
     */
    Span byteArray() {
        expect(TC_ARRAY);
        classDescription(BYTE_ARRAY);
        handles.add(NOT_REFERABLE);
        int length = integer();
        if (length < 0 || length > data.length - position) {
            throw KeyFileRefusal.unreadableKey();
        }
        Span content = new Span(position, length);
        position += length;
        return content;
    }

    /**
     * Reads a new constant of the enum.
     *
     * @param type the enum
     * @return the constant's name
     */
    String enumConstant(StreamClass type) {
        expect(TC_ENUM);
        classDescription(type);
        handles.add(NOT_REFERABLE);
        return string();
    }

    /** Refuses anything after what has been read. */
    void requireEnd() {
        if (position != data.length) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * A class description that must be one of the classes: a new one, which is checked against the class of its name
     * down to its superclasses, or a reference to one of them read before.
     */
    private StreamClass classDescription(StreamClass... classes) {
        int code = next();
        if (code == TC_REFERENCE) {
            StreamClass referenced = referenced(StreamClass.class);
            if (!List.of(classes).contains(referenced)) {
                throw KeyFileRefusal.unreadableKey();
            }
            return referenced;
        }
        if (code != TC_CLASSDESC) {
            throw KeyFileRefusal.unreadableKey();
        }
        String name = utf();
        StreamClass expected = Arrays
                .stream(classes)
                .filter(candidate -> candidate.name().equals(name))
                .findFirst()
                .orElseThrow(KeyFileRefusal::unreadableKey);
        if (longValue() != expected.serialUid()) {
            throw KeyFileRefusal.unreadableKey();
        }
        handles.add(expected);
        if (next() != (expected.flags() & 0xFF) || unsignedShort() != expected.fields().size()) {
            throw KeyFileRefusal.unreadableKey();
        }
        for (Field field : expected.fields()) {
            if (next() != field.type().charAt(0) || !field.name().equals(utf())) {
                throw KeyFileRefusal.unreadableKey();
            }
            string(field.type());
        }
        expect(TC_ENDBLOCKDATA);
        if (expected.superclass() == null) {
            expect(TC_NULL);
        } else {
            classDescription(expected.superclass());
        }
        return expected;
    }

    /** What the handle that follows stands for, which must be of the kind given. */
    private <T> T referenced(Class<T> kind) {
        long index = (long) integer() - BASE_WIRE_HANDLE;
        if (index < 0 || index >= handles.size() || !kind.isInstance(handles.get((int) index))) {
            throw KeyFileRefusal.unreadableKey();
        }
        return kind.cast(handles.get((int) index));
    }

    /** A string in the stream's modified UTF-8, after its length as an unsigned short. */
    private String utf() {
        int length = unsignedShort();
        require(length);
        try (DataInputStream string = new DataInputStream(
                new ByteArrayInputStream(data, position - Short.BYTES, Short.BYTES + length))) {
            String value = string.readUTF();
            position += length;
            return value;
        } catch (IOException e) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    private void expect(int code) {
        if (next() != code) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    private int next() {
        require(1);
        return data[position++] & 0xFF;
    }

    private int unsignedShort() {
        require(Short.BYTES);
        int value = Short.toUnsignedInt(numbers.getShort(position));
        position += Short.BYTES;
        return value;
    }

    private int integer() {
        require(Integer.BYTES);
        int value = numbers.getInt(position);
        position += Integer.BYTES;
        return value;
    }

    private long longValue() {
        require(Long.BYTES);
        long value = numbers.getLong(position);
        position += Long.BYTES;
        return value;
    }

    private void require(int count) {
        if (count > data.length - position) {
            throw KeyFileRefusal.unreadableKey();
        }
    }

    /**
     * A class as a stream describes it, the one shape a class description is read against.
     *
     * @param name the class's name, as {@link Class#getName()} gives it
     * @param serialUid the class's serialVersionUID
     * @param flags the class description's flags
     * @param fields the class's serializable fields, in the order the stream lists them
     * @param superclass the class's serializable superclass, or {@code null} when it has none
     */
    record StreamClass(String name, long serialUid, byte flags, List<Field> fields, StreamClass superclass) {
    }

    /**
     * A field of object type, as a stream describes it.
     *
     * @param name the field's name
     * @param type the field's type as a field descriptor, such as {@code [B} or {@code Ljava/lang/String;}
     */
    record Field(String name, String type) {
    }

    /**
     * Where a byte array's content stands in the bytes the stream is read from.
     *
     * @param offset where the content starts
     * @param length how many bytes it has
     */
    record Span(int offset, int length) {

        /**
         * A copy of the content, which the caller overwrites once it is used when it may hold a key.
         *
         * @param data the bytes the stream was read from
         * @return the content
         */
        byte[] copyFrom(byte[] data) {
            return Arrays.copyOfRange(data, offset, offset + length);
        }
    }
}
