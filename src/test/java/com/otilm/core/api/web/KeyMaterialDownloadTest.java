package com.otilm.core.api.web;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.core.io.Resource;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class KeyMaterialDownloadTest {

    private static final byte[] DER = new byte[300];

    static {
        for (int i = 0; i < DER.length; i++) {
            DER[i] = (byte) i;
        }
    }

    @Test
    void encryptedPrivateKeyPem_rendersTheMaterialAsPem() throws Exception {
        // when
        String pem = body(KeyMaterialDownload.encryptedPrivateKeyPem("signing key", DER));

        // then
        List<String> lines = pem.lines().toList();
        assertEquals("-----BEGIN ENCRYPTED PRIVATE KEY-----", lines.getFirst());
        assertEquals("-----END ENCRYPTED PRIVATE KEY-----", lines.getLast());
        List<String> body = lines.subList(1, lines.size() - 1);
        assertTrue(body.stream().allMatch(line -> line.length() <= 64), pem);
        assertArrayEquals(DER, Base64.getDecoder().decode(String.join("", body)));
    }

    @Test
    void encryptedPrivateKeyPem_isADownloadThatIsNeitherCachedNorSniffed() {
        // when
        ResponseEntity<Resource> download = KeyMaterialDownload.encryptedPrivateKeyPem("signing key", DER);

        // then
        HttpHeaders headers = download.getHeaders();
        ContentDisposition disposition = headers.getContentDisposition();
        assertTrue(disposition.isAttachment());
        assertEquals("signing_key.pem", disposition.getFilename());
        assertEquals("no-store, no-cache", headers.getCacheControl());
        assertEquals("no-cache", headers.getPragma());
        assertEquals("nosniff", headers.getFirst("X-Content-Type-Options"));
        assertEquals(MediaType.APPLICATION_OCTET_STREAM, headers.getContentType());
    }

    @ParameterizedTest
    @MethodSource("unsafeNames")
    void sanitizedFileName_keepsOnlyCharactersSafeInAFileName(String name, String expected) {
        // when
        String fileName = KeyMaterialDownload.sanitizedFileName(name, "pem");

        // then
        assertEquals(expected, fileName);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {"...", ".."})
    void sanitizedFileName_namesAKeyThatLeavesNothingUsable(String name) {
        // when
        String fileName = KeyMaterialDownload.sanitizedFileName(name, "pem");

        // then
        assertEquals("key.pem", fileName);
    }

    @Test
    void sanitizedFileName_shortensALongName() {
        // when
        String fileName = KeyMaterialDownload.sanitizedFileName("k".repeat(300), "pem");

        // then
        assertEquals("k".repeat(100) + ".pem", fileName);
    }

    private static Stream<Arguments> unsafeNames() {
        return Stream
                .of(arguments("../../etc/passwd", "_.._etc_passwd.pem"),
                        arguments("evil\"\r\nX-Injected: yes", "evil___X-Injected__yes.pem"),
                        arguments("Schlüssel 🔑", "Schl_ssel__.pem"), arguments("tls-key_v2.1", "tls-key_v2.1.pem"));
    }

    private static String body(ResponseEntity<Resource> download) throws Exception {
        return new String(download.getBody().getContentAsByteArray(), StandardCharsets.US_ASCII);
    }
}
