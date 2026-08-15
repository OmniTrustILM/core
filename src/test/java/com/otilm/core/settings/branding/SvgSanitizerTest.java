package com.otilm.core.settings.branding;

import com.otilm.api.exception.ValidationException;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Locale;
import javax.imageio.ImageIO;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Exercises the sanitizer through the path a logo actually takes — submitted as a data URI, stored as whatever comes
 * back — rather than against the DOM directly, so a payload that survives the round trip fails the test.
 */
class SvgSanitizerTest {

    private static final String FIELD = "lightLogo";
    private static final String OPEN = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 200 100'>";

    private static String submit(String svg) {
        String stored = BrandingLogoValidator
                .validateAndSanitize(FIELD, "data:image/svg+xml;base64,"
                        + Base64.getEncoder().encodeToString(svg.getBytes(StandardCharsets.UTF_8)));
        return new String(Base64.getDecoder().decode(stored.substring(stored.indexOf(',') + 1)),
                StandardCharsets.UTF_8);
    }

    @Test
    void aScriptElementDoesNotSurvive() {
        String stored = submit(OPEN + "<script>alert(1)</script><rect width='200' height='100'/></svg>");

        Assertions.assertFalse(stored.toLowerCase(Locale.ROOT).contains("script"), stored);
        Assertions.assertFalse(stored.contains("alert(1)"), stored);
    }

    @ParameterizedTest
    @ValueSource(strings = {"onload", "onclick", "onmouseover", "onbegin", "onfocusin"})
    void noEventHandlerAttributeSurvives(String handler) {
        String stored = submit(OPEN + "<rect width='200' height='100' " + handler + "='alert(1)'/></svg>");

        Assertions.assertFalse(stored.toLowerCase(Locale.ROOT).contains(handler), stored);
        Assertions.assertFalse(stored.contains("alert(1)"), stored);
    }

    @Test
    void aJavascriptUrlDoesNotSurvive() {
        String stored = submit(OPEN + "<a href='javascript:alert(1)'><rect width='200' height='100'/></a></svg>");

        Assertions.assertFalse(stored.contains("javascript:"), stored);
    }

    /** A nested data URI is another way to smuggle a document in, so a reference that is not local is dropped. */
    @Test
    void aNestedDataUrlDoesNotSurvive() {
        String stored = submit(
                OPEN + "<image href='data:image/svg+xml;base64,PHN2Zy8+' width='200' height='100'/>" + "</svg>");

        Assertions.assertFalse(stored.contains("data:"), stored);
    }

    @Test
    void anExternalReferenceDoesNotSurvive() {
        String withXlink = "<svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink' "
                + "viewBox='0 0 200 100'>";

        String stored = submit(withXlink + "<use xlink:href='https://attacker.example/evil.svg#x'/>"
                + "<image href='https://attacker.example/pixel.png' width='10' height='10'/></svg>");

        Assertions.assertFalse(stored.contains("attacker.example"), stored);
    }

    /** A reference inside the same document is how gradients and symbols work, so it has to be left alone. */
    @Test
    void aLocalReferenceSurvives() {
        String stored = submit(OPEN + "<defs><linearGradient id='g'><stop offset='0' stop-color='#fff'/>"
                + "</linearGradient></defs><rect width='200' height='100' fill='url(#g)'/></svg>");

        Assertions.assertTrue(stored.contains("linearGradient"), stored);
        Assertions.assertTrue(stored.contains("url(#g)"), stored);
    }

    @Test
    void aForeignObjectDoesNotSurvive() {
        String stored = submit(OPEN + "<foreignObject width='200' height='100'>"
                + "<body xmlns='http://www.w3.org/1999/xhtml'><img src='x' onerror='alert(1)'/></body>"
                + "</foreignObject></svg>");

        Assertions.assertFalse(stored.contains("foreignObject"), stored);
        Assertions.assertFalse(stored.contains("onerror"), stored);
    }

    /**
     * The reason elements are allow-listed rather than deny-listed: {@code animate} rewrites an attribute after load,
     * and no list of "the dangerous elements" written today would have named it.
     */
    @Test
    void anElementOutsideTheAllowListDoesNotSurvive() {
        String stored = submit(OPEN + "<rect width='200' height='100'>"
                + "<animate attributeName='href' to='javascript:alert(1)'/></rect></svg>");

        Assertions.assertFalse(stored.contains("animate"), stored);
        Assertions.assertFalse(stored.contains("javascript:"), stored);
    }

    @Test
    void cssThatFetchesDoesNotSurvive() {
        String stored = submit(OPEN + "<style>@import url('https://attacker.example/x.css');</style>"
                + "<rect width='200' height='100'/></svg>");

        Assertions.assertFalse(stored.contains("@import"), stored);
        Assertions.assertFalse(stored.contains("attacker.example"), stored);
    }

    @Test
    void aStyleAttributeThatFetchesDoesNotSurvive() {
        String stored = submit(
                OPEN + "<rect width='200' height='100' style=\"fill:url(https://attacker.example/x.svg#g)\"/></svg>");

        Assertions.assertFalse(stored.contains("attacker.example"), stored);
    }

    @Test
    void anExternalStylesheetProcessingInstructionDoesNotSurvive() {
        String stored = submit("<?xml-stylesheet href='https://attacker.example/x.css' type='text/css'?>" + OPEN
                + "<rect width='200' height='100'/></svg>");

        Assertions.assertFalse(stored.contains("xml-stylesheet"), stored);
        Assertions.assertFalse(stored.contains("attacker.example"), stored);
    }

    /** Sanitizing must not quietly turn a logo into a blank rectangle; the drawing itself has to come through. */
    @Test
    void aBenignLogoSurvivesIntact() {
        String stored = submit(
                OPEN + "<title>Acme</title>" + "<path d='M0 0 L200 0 L200 100 Z' fill='#0073CF' stroke-width='2'/>"
                        + "<text x='10' y='50' font-family='sans-serif'>Acme</text></svg>");

        Assertions.assertTrue(stored.contains("<title>Acme</title>"), stored);
        Assertions.assertTrue(stored.contains("M0 0 L200 0 L200 100 Z"), stored);
        Assertions.assertTrue(stored.contains("#0073CF"), stored);
        Assertions.assertTrue(stored.contains("font-family=\"sans-serif\""), stored);
        Assertions.assertTrue(stored.contains("viewBox=\"0 0 200 100\""), stored);
    }

    /** Storing a partially sanitized document would be worse than refusing it, so a broken one is refused. */
    @Test
    void aDocumentThatCannotBeParsedIsRejectedRatherThanRepaired() {
        String truncated = "data:image/svg+xml;base64," + Base64
                .getEncoder()
                .encodeToString("<svg xmlns='http://www.w3.org/2000/svg'><rect".getBytes(StandardCharsets.UTF_8));

        Assertions
                .assertThrows(ValidationException.class,
                        () -> BrandingLogoValidator.validateAndSanitize(FIELD, truncated));
    }

    /** A PNG has no executable content to strip, so it must come back byte for byte as it was submitted. */
    @Test
    void aPngIsStoredUnchanged() {
        ByteArrayOutputStream png = new ByteArrayOutputStream();
        try {
            ImageIO.write(new BufferedImage(200, 100, BufferedImage.TYPE_INT_RGB), "png", png);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        String submitted = "data:image/png;base64," + Base64.getEncoder().encodeToString(png.toByteArray());

        Assertions.assertEquals(submitted, BrandingLogoValidator.validateAndSanitize(FIELD, submitted));
    }
}
