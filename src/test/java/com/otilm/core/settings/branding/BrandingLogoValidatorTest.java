package com.otilm.core.settings.branding;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.settings.BrandingSettingsUpdateDto;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.CRC32;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

class BrandingLogoValidatorTest {

    private static final String FIELD = "lightLogo";

    /** A complete PNG, not a hand-built header: the validator walks the whole chunk sequence and checks every CRC. */
    private static byte[] png(int width, int height) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try {
            ImageIO.write(new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB), "png", bytes);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        return bytes.toByteArray();
    }

    /** Signature, IHDR chunk length and tag, then the two dimensions — everything a header-only reader would need. */
    private static byte[] pngHeaderOnly(int width, int height) {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        bytes.writeBytes(new byte[]{(byte) 0x89, 'P', 'N', 'G', '\r', '\n', 0x1A, '\n'});
        bytes.writeBytes(new byte[]{0, 0, 0, 13});
        bytes.writeBytes("IHDR".getBytes(StandardCharsets.US_ASCII));
        bytes.writeBytes(fourBytes(width));
        bytes.writeBytes(fourBytes(height));
        return bytes.toByteArray();
    }

    private static byte[] fourBytes(int value) {
        return new byte[]{(byte) (value >>> 24), (byte) (value >>> 16), (byte) (value >>> 8), (byte) value};
    }

    private static String dataUri(String mediaType, byte[] content) {
        return "data:" + mediaType + ";base64," + Base64.getEncoder().encodeToString(content);
    }

    private static String pngLogo(int width, int height) {
        return dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, png(width, height));
    }

    private static String svgLogo(String svg) {
        return dataUri(BrandingLogoValidator.SVG_MEDIA_TYPE, svg.getBytes(StandardCharsets.UTF_8));
    }

    private static String rejectionMessage(String logo) {
        return Assertions
                .assertThrows(ValidationException.class, () -> BrandingLogoValidator.validate(FIELD, logo))
                .getMessage();
    }

    /** Clearing a slot is how an operator removes a logo, so the absent value is the common case, not an error. */
    @Test
    void aClearedSlotIsAccepted() {
        Assertions.assertDoesNotThrow(() -> BrandingLogoValidator.validate(FIELD, null));
    }

    @ParameterizedTest
    @CsvSource({"200,200", "300,100", "240,120", "1,1", "3,1"})
    void aPngWithinTheAllowedAspectRatioIsAccepted(int width, int height) {
        Assertions.assertDoesNotThrow(() -> BrandingLogoValidator.validate(FIELD, pngLogo(width, height)));
    }

    /** The boundaries are inclusive, so 1:1 and 3:1 pass and anything a hair outside them does not. */
    @ParameterizedTest
    @CsvSource({"301,100", "400,100", "199,200", "100,300"})
    void aPngOutsideTheAllowedAspectRatioIsRejected(int width, int height) {
        Assertions.assertTrue(rejectionMessage(pngLogo(width, height)).contains("aspect ratio"));
    }

    /**
     * A width or height of zero cannot come out of a real encoder, so the fixture is hand-built; the CRCs are still the
     * ones the chunks require, leaving the dimension as the only thing wrong with it.
     */
    @Test
    void aPngWithNoWidthOrHeightIsRejected() {
        byte[] zeroWidth = png(200, 100);
        System.arraycopy(fourBytes(0), 0, zeroWidth, 16, 4);
        repairChunkCrc(zeroWidth, 8);

        Assertions
                .assertTrue(rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, zeroWidth))
                        .contains("zero width or height"));
    }

    /**
     * The point of sniffing: the declared media type is the attacker-controlled part, so an SVG announced as a PNG has
     * to be refused rather than stored and later served.
     */
    @Test
    void contentThatContradictsTheDeclaredMediaTypeIsRejected() {
        String svgLabelledAsPng = dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE,
                "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 2 1'/>".getBytes(StandardCharsets.UTF_8));

        Assertions
                .assertTrue(rejectionMessage(svgLabelledAsPng)
                        .contains("declares media type image/png but its content is an SVG document"));
    }

    @Test
    void aPngLabelledAsSvgIsRejected() {
        String pngLabelledAsSvg = dataUri(BrandingLogoValidator.SVG_MEDIA_TYPE, png(200, 100));

        Assertions
                .assertTrue(rejectionMessage(pngLabelledAsSvg)
                        .contains("declares media type image/svg+xml but its content is a PNG image"));
    }

    /**
     * Content sniffing decides the format, so a payload that is neither PNG nor SVG gets one rejection whatever it
     * claims to be — the declared type never gets a say.
     */
    @ParameterizedTest
    @ValueSource(strings = {BrandingLogoValidator.PNG_MEDIA_TYPE, BrandingLogoValidator.SVG_MEDIA_TYPE, "image/jpeg"})
    void contentThatIsNeitherAPngNorAnSvgIsRejectedWhateverItDeclares(String mediaType) {
        String jpeg = dataUri(mediaType, new byte[]{(byte) 0xFF, (byte) 0xD8, (byte) 0xFF, (byte) 0xE0, 0, 0x10});

        Assertions.assertTrue(rejectionMessage(jpeg).contains("neither a PNG image nor a parseable SVG document"));
    }

    /** Four bytes of the signature is not the signature, so the content sniffs as neither format. */
    @Test
    void aPayloadTooShortToCarryTheSignatureIsRejected() {
        String truncated = dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, new byte[]{(byte) 0x89, 'P', 'N', 'G'});

        Assertions.assertTrue(rejectionMessage(truncated).contains("neither a PNG image nor a parseable SVG document"));
    }

    /**
     * The header alone was once enough, which meant the dimensions were read off bytes that no decoder would accept as
     * an image. IHDR has to be closed by its own CRC and the file by IEND before the width and height mean anything.
     */
    @Test
    void aPngThatIsNothingButAHeaderIsRejected() {
        String headerOnly = dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, pngHeaderOnly(200, 100));

        Assertions.assertTrue(rejectionMessage(headerOnly).contains("not a well-formed PNG image"));
    }

    @Test
    void aPngTruncatedBeforeItsEndChunkIsRejected() {
        byte[] complete = png(200, 100);
        byte[] truncated = new byte[complete.length - 12];
        System.arraycopy(complete, 0, truncated, 0, truncated.length);

        Assertions
                .assertTrue(rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, truncated))
                        .contains("not a well-formed PNG image"));
    }

    /** A chunk that has been edited no longer matches the CRC it carries, which is how the edit is caught. */
    @Test
    void aPngWithACorruptedChunkIsRejected() {
        byte[] corrupted = png(200, 100);
        corrupted[corrupted.length - 8] ^= 0x01;

        Assertions
                .assertTrue(rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, corrupted))
                        .contains("not a well-formed PNG image"));
    }

    /** Dimensions are read out of IHDR, so a first chunk that merely looks the right length must not be trusted. */
    @Test
    void aPngWhoseFirstChunkIsNotIhdrIsRejected() {
        byte[] content = png(200, 100);
        System.arraycopy("gAMA".getBytes(StandardCharsets.US_ASCII), 0, content, 12, 4);
        repairChunkCrc(content, 8);

        Assertions
                .assertTrue(rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, content))
                        .contains("not a well-formed PNG image"));
    }

    /** Rewrites the CRC of the chunk starting at {@code offset}, so a deliberate edit is not caught as corruption. */
    private static void repairChunkCrc(byte[] content, int offset) {
        int dataLength = ((content[offset] & 0xFF) << 24) | ((content[offset + 1] & 0xFF) << 16)
                | ((content[offset + 2] & 0xFF) << 8) | (content[offset + 3] & 0xFF);
        CRC32 crc = new CRC32();
        crc.update(content, offset + 4, 4 + dataLength);
        System.arraycopy(fourBytes((int) crc.getValue()), 0, content, offset + 8 + dataLength, 4);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "<svg xmlns='http://www.w3.org/2000/svg' width='200' height='100'/>",
            "<svg xmlns='http://www.w3.org/2000/svg' width='200px' height='100px'/>",
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 240 120'/>",
            "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0,0,240,120'/>",
            "<svg width='100' height='100'/>"})
    void anSvgWithReadableProportionsInsideTheRangeIsAccepted(String svg) {
        Assertions.assertDoesNotThrow(() -> BrandingLogoValidator.validate(FIELD, svgLogo(svg)));
    }

    @Test
    void anSvgOutsideTheAllowedAspectRatioIsRejected() {
        String wide = "<svg xmlns='http://www.w3.org/2000/svg' width='500' height='100'/>";

        Assertions.assertTrue(rejectionMessage(svgLogo(wide)).contains("aspect ratio"));
    }

    @Test
    void anSvgWithNeitherDimensionsNorViewBoxIsRejected() {
        String bare = "<svg xmlns='http://www.w3.org/2000/svg'><rect width='10' height='10'/></svg>";

        Assertions
                .assertTrue(rejectionMessage(svgLogo(bare)).contains("neither usable width and height nor a viewBox"));
    }

    /**
     * Every comparison against {@code NaN} is false, so a viewBox carrying one would pass a range check by failing both
     * halves of it. {@code Infinity} parses just as readily and divides into a ratio that is not a number either.
     */
    @ParameterizedTest
    @ValueSource(strings = {
            "0 0 NaN NaN",
            "0 0 NaN 100",
            "0 0 200 NaN",
            "0 0 Infinity 100",
            "0 0 Infinity Infinity",
            "0 0 200 Infinity",
            "0 0 -Infinity 100"})
    void anSvgWhoseViewBoxIsNotAFiniteSizeIsRejected(String viewBox) {
        String svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='%s'/>".formatted(viewBox);

        Assertions.assertTrue(rejectionMessage(svgLogo(svg)).contains("neither usable width and height nor a viewBox"));
    }

    /**
     * A percentage is relative to whatever renders the logo, so it carries no intrinsic proportions; the viewBox does,
     * and is used instead when it is there.
     */
    @Test
    void anSvgSizedInPercentagesFallsBackToItsViewBox() {
        String relative = "<svg xmlns='http://www.w3.org/2000/svg' width='100%' height='100%' viewBox='0 0 200 100'/>";

        Assertions.assertDoesNotThrow(() -> BrandingLogoValidator.validate(FIELD, svgLogo(relative)));
    }

    @Test
    void anSvgSizedInPercentagesWithoutAViewBoxIsRejected() {
        String relative = "<svg xmlns='http://www.w3.org/2000/svg' width='100%' height='50%'/>";

        Assertions
                .assertTrue(
                        rejectionMessage(svgLogo(relative)).contains("neither usable width and height nor a viewBox"));
    }

    /**
     * Comparing a width in millimetres against a height in pixels as if they were the same unit would let a badly
     * proportioned logo through, so mismatched units defer to the viewBox rather than guess a conversion.
     */
    @Test
    void anSvgMixingUnitsBetweenWidthAndHeightFallsBackToItsViewBox() {
        String mixed = "<svg xmlns='http://www.w3.org/2000/svg' width='50mm' height='100px' viewBox='0 0 200 100'/>";

        Assertions.assertDoesNotThrow(() -> BrandingLogoValidator.validate(FIELD, svgLogo(mixed)));
    }

    @Test
    void anXmlDocumentThatIsNotAnSvgIsRejected() {
        Assertions
                .assertTrue(rejectionMessage(svgLogo("<html><body>hello</body></html>"))
                        .contains("neither a PNG image nor a parseable SVG document"));
    }

    /**
     * Reading the dimensions means parsing operator-supplied XML. With entity resolution left on, a logo would be a way
     * to read files off the server, so the parser refuses a document type declaration outright.
     */
    @Test
    void anSvgCarryingADoctypeIsRejectedRatherThanResolved() {
        String withEntity = """
                <?xml version="1.0"?>
                <!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 100"><title>&xxe;</title></svg>
                """;

        Assertions
                .assertTrue(rejectionMessage(svgLogo(withEntity))
                        .contains("neither a PNG image nor a parseable SVG document"));
    }

    @Test
    void aLogoLargerThanTheAllowedSizeIsRejected() {
        byte[] header = pngHeaderOnly(200, 100);
        byte[] oversized = new byte[BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES + 1];
        System.arraycopy(header, 0, oversized, 0, header.length);

        String message = rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, oversized));

        Assertions.assertTrue(message.contains("the maximum is"), message);
        Assertions.assertTrue(message.contains(String.valueOf(BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES)));
    }

    /**
     * The encoded string is bounded before the regex runs and before anything is decoded, so a caller reaching the
     * service directly cannot make it allocate a payload it was always going to refuse.
     */
    @Test
    void aLogoTooLongToBeWithinTheSizeLimitIsRejectedWithoutBeingDecoded() {
        String overlong = "data:image/png;base64," + "A".repeat(BrandingSettingsUpdateDto.LOGO_MAX_LENGTH);

        String message = rejectionMessage(overlong);

        Assertions.assertTrue(message.contains("encoded characters"), message);
        Assertions.assertTrue(message.contains(String.valueOf(BrandingSettingsUpdateDto.LOGO_MAX_LENGTH)), message);
    }

    /**
     * The decoded bound is inclusive and is still the one that decides: a payload of exactly the maximum clears it and
     * goes on to be judged on its content, rather than being refused for its size.
     */
    @Test
    void aLogoExactlyAtTheAllowedSizeClearsTheSizeCheck() {
        byte[] atLimit = new byte[BrandingSettingsUpdateDto.LOGO_MAX_DECODED_BYTES];
        byte[] header = pngHeaderOnly(200, 100);
        System.arraycopy(header, 0, atLimit, 0, header.length);

        String message = rejectionMessage(dataUri(BrandingLogoValidator.PNG_MEDIA_TYPE, atLimit));

        Assertions.assertFalse(message.contains("the maximum is"), message);
        Assertions.assertTrue(message.contains("not a well-formed PNG image"), message);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "iVBORw0KGgo=",
            "https://example.com/logo.png",
            "data:image/svg+xml,<svg/>",
            "data:image/png;base64,not base64!"})
    void anythingOtherThanABase64DataUriIsRejected(String candidate) {
        Assertions.assertTrue(rejectionMessage(candidate).contains("base64 data URI"));
    }

    /** Every rejection has to name the slot, or the Appearance form cannot say which upload was refused. */
    @Test
    void everyRejectionNamesTheFieldItCameFrom() {
        Assertions
                .assertTrue(Assertions
                        .assertThrows(ValidationException.class,
                                () -> BrandingLogoValidator.validate("darkLogo", pngLogo(500, 100)))
                        .getMessage()
                        .contains("'darkLogo'"));
    }
}
