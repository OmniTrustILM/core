package com.otilm.core.key.normalization;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * How deeply an ASN.1 encoding nests constructed values, read from its tags and lengths alone, so that a limit holds
 * before anything parses the encoding. An encoding this cannot read is left for the parser to refuse.
 */
final class NestingDepth {

    private static final int INDEFINITE = -1;

    private NestingDepth() {
    }

    /**
     * Whether no constructed value in the encoding nests deeper than the maximum.
     *
     * @param encoding a BER or DER encoding
     * @param maximum the deepest nesting allowed
     * @return {@code false} when a constructed value nests deeper than {@code maximum}
     */
    static boolean within(byte[] encoding, int maximum) {
        Deque<Integer> ends = new ArrayDeque<>();
        int position = 0;
        while (position < encoding.length) {
            closeFinished(ends, position);
            if (closesIndefinite(ends, encoding, position)) {
                ends.pop();
                position += 2;
                continue;
            }
            Header header = Header.at(encoding, position);
            if (header == null) {
                return true;
            }
            if (header.constructed()) {
                ends.push(header.end());
                if (ends.size() > maximum) {
                    return false;
                }
                position = header.contentStart();
            } else {
                position = header.end();
            }
        }
        return true;
    }

    private static void closeFinished(Deque<Integer> ends, int position) {
        while (!ends.isEmpty() && ends.peek() != INDEFINITE && position >= ends.peek()) {
            ends.pop();
        }
    }

    private static boolean closesIndefinite(Deque<Integer> ends, byte[] encoding, int position) {
        return !ends.isEmpty() && ends.peek() == INDEFINITE && position + 1 < encoding.length && encoding[position] == 0
                && encoding[position + 1] == 0;
    }

    /**
     * A value's identifier and length: where its contents start, and where it ends or {@link #INDEFINITE} for a
     * constructed value of indefinite length.
     */
    private record Header(boolean constructed, int contentStart, int end) {

        /** The header at the offset, or {@code null} when it runs past the encoding or is malformed. */
        static Header at(byte[] encoding, int offset) {
            int identifier = encoding[offset] & 0xFF;
            int position = offset + 1;
            if ((identifier & 0x1F) == 0x1F) {
                position = afterHighTagNumber(encoding, position);
            }
            if (position >= encoding.length) {
                return null;
            }
            boolean constructed = (identifier & 0x20) != 0;
            int first = encoding[position++] & 0xFF;
            if (first == 0x80) {
                return constructed ? new Header(true, position, INDEFINITE) : null;
            }
            long length = first;
            if (first > 0x80) {
                int octets = first & 0x7F;
                if (octets > 4 || position + octets > encoding.length) {
                    return null;
                }
                length = 0;
                for (int i = 0; i < octets; i++) {
                    length = (length << 8) | (encoding[position++] & 0xFF);
                }
            }
            long end = position + length;
            return end > encoding.length ? null : new Header(constructed, position, (int) end);
        }

        private static int afterHighTagNumber(byte[] encoding, int start) {
            int position = start;
            while (position < encoding.length && (encoding[position] & 0x80) != 0) {
                position++;
            }
            return position + 1;
        }
    }
}
