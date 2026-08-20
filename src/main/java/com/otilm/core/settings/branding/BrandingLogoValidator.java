package com.otilm.core.settings.branding;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import java.util.Objects;
import java.util.OptionalDouble;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.CRC32;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Validates a branding logo submitted as a base64 data URI.
 *
 * <p>
 * The format is decided by looking at the decoded bytes, never by the media type the caller declared: a caller that
 * labels an SVG as {@code image/png} is refused rather than trusted. The declared type still has to agree with what the
 * content turns out to be, because a disagreement is either a mistake or an attempt to slip markup past a check that
 * reads the label.
 */
public final class BrandingLogoValidator {

    public static final String PNG_MEDIA_TYPE = "image/png";
    public static final String SVG_MEDIA_TYPE = "image/svg+xml";

    static final double MIN_ASPECT_RATIO = 1.0;
    static final double MAX_ASPECT_RATIO = 3.0;

    private static final String SVG_NAMESPACE = "http://www.w3.org/2000/svg";
    private static final String SVG_ROOT_ELEMENT = "svg";

    private static final Pattern DATA_URI = Pattern.compile("^data:([^;,]+);base64,([A-Za-z0-9+/]+={0,2})$");

    private static final String MALFORMED_REASON = "must be a base64 data URI with media type %s or %s"
            .formatted(PNG_MEDIA_TYPE, SVG_MEDIA_TYPE);

    private static final String UNRECOGNISED_REASON = "is neither a PNG image nor a parseable SVG document";

    /** A number, then an optional absolute or font-relative unit. A percentage carries no intrinsic size. */
    private static final Pattern SVG_LENGTH = Pattern
            .compile("^\\s*(\\d+(?:\\.\\d+)?)\\s*(px|pt|pc|cm|mm|in|em|ex)?\\s*$");

    private static final byte[] PNG_SIGNATURE = {(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'};

    /** Chunk length, chunk type and the trailing CRC — everything in a chunk that is not its data. */
    private static final int PNG_CHUNK_OVERHEAD = 12;
    private static final int PNG_CHUNK_TYPE_LENGTH = 4;
    private static final int PNG_IHDR_DATA_LENGTH = 13;

    private static final String PNG_HEADER_CHUNK = "IHDR";
    private static final String PNG_IMAGE_DATA_CHUNK = "IDAT";
    private static final String PNG_END_CHUNK = "IEND";

    private BrandingLogoValidator() {
    }

    /**
     * Validates a submitted logo and returns the form of it that may be stored. An SVG comes back sanitized, so the
     * original is never what reaches the settings table; a PNG comes back unchanged, having no executable content to
     * remove.
     *
     * @param field the branding field the logo was submitted under, so a rejection names the slot the operator sees
     * @param dataUri the submitted value; {@code null} means the slot is being cleared and is always accepted
     * @return the value to store, or {@code null} when the slot is being cleared
     */
    public static String validateAndSanitize(String field, String dataUri) {
        if (dataUri == null) {
            return null;
        }

        // Bounded before the regex runs and before anything is decoded: a payload this long cannot decode to a
        // permitted size, so refusing it on the string spares the allocation a direct service caller would otherwise
        // force. Bean Validation applies the same bound, but only on the controller path.
        if (dataUri.length() > BrandingSettingsUpdateDto.LOGO_MAX_LENGTH) {
            throw reject(field,
                    "is %d encoded characters; the maximum is %d, being %d decoded bytes"
                            .formatted(dataUri.length(), BrandingSettingsUpdateDto.LOGO_MAX_LENGTH,
                                    BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES));
        }

        Matcher matcher = DATA_URI.matcher(dataUri);
        if (!matcher.matches()) {
            throw reject(field, MALFORMED_REASON);
        }

        String declaredMediaType = matcher.group(1).toLowerCase(Locale.ROOT);
        byte[] content = decode(field, matcher.group(2));

        if (content.length > BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES) {
            throw reject(field, "is %d bytes; the maximum is %d bytes"
                    .formatted(content.length, BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES));
        }

        if (startsWithPngSignature(content)) {
            requireDeclared(field, declaredMediaType, PNG_MEDIA_TYPE, "a PNG image");
            validatePng(field, content);
            return dataUri;
        }

        Element svgRoot = svgRootOrNull(content);
        if (svgRoot != null) {
            requireDeclared(field, declaredMediaType, SVG_MEDIA_TYPE, "an SVG document");
            return sanitizedSvg(field, svgRoot);
        }

        throw reject(field, UNRECOGNISED_REASON);
    }

    /**
     * The content has already decided the format; the declaration only has to agree with it. A disagreement is refused
     * rather than resolved in favour of the content, because a caller that mislabels a logo either has a bug or is
     * probing for a check that reads the label.
     */
    private static void requireDeclared(String field, String declaredMediaType, String expected, String content) {
        if (!expected.equals(declaredMediaType)) {
            throw reject(field, "declares media type %s but its content is %s".formatted(declaredMediaType, content));
        }
    }

    private static byte[] decode(String field, String payload) {
        try {
            return Base64.getDecoder().decode(payload);
        } catch (IllegalArgumentException e) {
            throw reject(field, "is not valid base64");
        }
    }

    private static boolean startsWithPngSignature(byte[] content) {
        if (content.length < PNG_SIGNATURE.length) {
            return false;
        }
        for (int i = 0; i < PNG_SIGNATURE.length; i++) {
            if (content[i] != PNG_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    private static void validatePng(String field, byte[] content) {
        long[] dimensions = pngDimensions(field, content);
        validateAspectRatio(field, dimensions[0], dimensions[1]);
    }

    /**
     * Walks the chunk sequence rather than reading the dimensions off a fixed offset, so the bytes have to be a whole
     * PNG — IHDR first at its declared length, every chunk's CRC intact, image data present and IEND closing the file
     * exactly at its end — before the width and height at the front of IHDR mean anything. Every step is bounded by the
     * already size-checked array, so a truncated or hostile chunk length terminates the walk instead of driving it.
     */
    private static long[] pngDimensions(String field, byte[] content) {
        long[] dimensions = null;
        boolean sawImageData = false;

        for (int offset = PNG_SIGNATURE.length; offset + PNG_CHUNK_OVERHEAD <= content.length;) {
            long dataLength = readUnsignedInt(content, offset);
            if (dataLength > content.length - offset - PNG_CHUNK_OVERHEAD) {
                throw invalidPng(field);
            }

            int typeOffset = offset + PNG_CHUNK_TYPE_LENGTH;
            String type = chunkType(content, typeOffset);
            if (!hasIntactCrc(content, typeOffset, (int) dataLength)) {
                throw invalidPng(field);
            }

            if (dimensions == null) {
                if (!PNG_HEADER_CHUNK.equals(type) || dataLength != PNG_IHDR_DATA_LENGTH) {
                    throw invalidPng(field);
                }
                int dataOffset = typeOffset + PNG_CHUNK_TYPE_LENGTH;
                dimensions = new long[]{readUnsignedInt(content, dataOffset), readUnsignedInt(content, dataOffset + 4)};
            } else if (PNG_HEADER_CHUNK.equals(type)) {
                throw invalidPng(field);
            } else if (PNG_IMAGE_DATA_CHUNK.equals(type)) {
                sawImageData = true;
            } else if (PNG_END_CHUNK.equals(type)) {
                boolean closesTheFile = dataLength == 0 && sawImageData
                        && offset + PNG_CHUNK_OVERHEAD == content.length;
                if (!closesTheFile) {
                    throw invalidPng(field);
                }
                return dimensions;
            }

            offset += PNG_CHUNK_OVERHEAD + (int) dataLength;
        }

        throw invalidPng(field);
    }

    private static String chunkType(byte[] content, int typeOffset) {
        return new String(content, typeOffset, PNG_CHUNK_TYPE_LENGTH, StandardCharsets.US_ASCII);
    }

    /** The CRC covers the chunk type and its data, and sits in the four bytes that follow them. */
    private static boolean hasIntactCrc(byte[] content, int typeOffset, int dataLength) {
        CRC32 crc = new CRC32();
        crc.update(content, typeOffset, PNG_CHUNK_TYPE_LENGTH + dataLength);
        return crc.getValue() == readUnsignedInt(content, typeOffset + PNG_CHUNK_TYPE_LENGTH + dataLength);
    }

    private static long readUnsignedInt(byte[] content, int offset) {
        return ((long) (content[offset] & 0xFF) << 24) | ((long) (content[offset + 1] & 0xFF) << 16)
                | ((long) (content[offset + 2] & 0xFF) << 8) | (content[offset + 3] & 0xFF);
    }

    /**
     * The stored value is built from the sanitized document rather than from the submitted bytes, so there is no path
     * by which the original — scripts, event handlers, external references and all — reaches the settings table.
     */
    private static String sanitizedSvg(String field, Element root) {
        OptionalDouble ratio = ratioFromWidthAndHeight(root);
        if (ratio.isEmpty()) {
            ratio = ratioFromViewBox(root);
        }
        if (ratio.isEmpty()) {
            throw reject(field, "is an SVG with neither usable width and height nor a viewBox, "
                    + "so its aspect ratio cannot be determined");
        }
        validateRatio(field, ratio.getAsDouble());

        Document document = root.getOwnerDocument();
        SvgSanitizer.sanitize(document);
        try {
            return "data:%s;base64,%s"
                    .formatted(SVG_MEDIA_TYPE,
                            Base64
                                    .getEncoder()
                                    .encodeToString(SvgSanitizer.serialize(document).getBytes(StandardCharsets.UTF_8)));
        } catch (TransformerException e) {
            throw reject(field, "is an SVG that could not be rewritten after sanitization");
        }
    }

    /** {@code null} rather than a rejection: content that is not an SVG may still be a PNG, and the caller decides. */
    private static Element svgRootOrNull(byte[] content) {
        Document document;
        try {
            document = secureDocumentBuilderFactory().newDocumentBuilder().parse(new ByteArrayInputStream(content));
        } catch (Exception e) {
            return null;
        }

        Element root = document.getDocumentElement();
        boolean isSvg = root != null
                && SVG_ROOT_ELEMENT.equals(root.getLocalName() == null ? root.getNodeName() : root.getLocalName())
                && (root.getNamespaceURI() == null || SVG_NAMESPACE.equals(root.getNamespaceURI()));
        return isSvg ? root : null;
    }

    /**
     * Entity resolution and DTD processing are off, so an SVG cannot be used to read files off the server or stall the
     * parser while its dimensions are being read.
     */
    private static DocumentBuilderFactory secureDocumentBuilderFactory() throws ParserConfigurationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        factory.setNamespaceAware(true);
        return factory;
    }

    /**
     * Only used when both lengths carry the same unit. Millimetres against pixels would need a conversion this does not
     * do, and guessing there would let a badly proportioned logo through; the viewBox answers the same question without
     * units at all, so that is the fallback.
     */
    private static OptionalDouble ratioFromWidthAndHeight(Element root) {
        Matcher width = SVG_LENGTH.matcher(root.getAttribute("width"));
        Matcher height = SVG_LENGTH.matcher(root.getAttribute("height"));
        if (!width.matches() || !height.matches()) {
            return OptionalDouble.empty();
        }
        if (!Objects.equals(width.group(2), height.group(2))) {
            return OptionalDouble.empty();
        }
        return ratioOf(Double.parseDouble(width.group(1)), Double.parseDouble(height.group(1)));
    }

    /** {@code viewBox="minX minY width height"} — the last two values are the intrinsic proportions. */
    private static OptionalDouble ratioFromViewBox(Element root) {
        String[] parts = root.getAttribute("viewBox").trim().split("[\\s,]+");
        if (parts.length != 4) {
            return OptionalDouble.empty();
        }
        try {
            return ratioOf(Double.parseDouble(parts[2]), Double.parseDouble(parts[3]));
        } catch (NumberFormatException e) {
            return OptionalDouble.empty();
        }
    }

    /**
     * {@code Double.parseDouble} accepts {@code NaN} and {@code Infinity}, and every comparison against {@code NaN} is
     * false, so a viewBox carrying either would otherwise satisfy the range check by failing both halves of it. A
     * dimension that is not a finite positive number leaves the ratio undetermined, which is the caller's fallback.
     */
    private static OptionalDouble ratioOf(double width, double height) {
        if (!Double.isFinite(width) || !Double.isFinite(height) || width <= 0 || height <= 0) {
            return OptionalDouble.empty();
        }
        double ratio = width / height;
        return Double.isFinite(ratio) ? OptionalDouble.of(ratio) : OptionalDouble.empty();
    }

    private static void validateAspectRatio(String field, long width, long height) {
        if (width <= 0 || height <= 0) {
            throw reject(field, "has a zero width or height");
        }
        validateRatio(field, (double) width / height);
    }

    private static void validateRatio(String field, double ratio) {
        if (ratio < MIN_ASPECT_RATIO || ratio > MAX_ASPECT_RATIO) {
            throw reject(field, "has an aspect ratio of %.2f:1; it must be between %.0f:1 and %.0f:1"
                    .formatted(ratio, MIN_ASPECT_RATIO, MAX_ASPECT_RATIO));
        }
    }

    private static ValidationException invalidPng(String field) {
        return reject(field, "is not a well-formed PNG image");
    }

    private static ValidationException reject(String field, String reason) {
        return new ValidationException("Branding logo '%s' %s.".formatted(field, reason));
    }
}
