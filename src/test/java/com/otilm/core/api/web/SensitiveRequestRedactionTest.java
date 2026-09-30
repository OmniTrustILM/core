package com.otilm.core.api.web;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.certificate.CertificateKeystoreRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.inspection.InspectionRequestDto;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.service.CertificateImportExternalService;
import com.otilm.core.service.CertificateKeystoreExternalService;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyImportExternalService;
import com.otilm.core.service.FileInspectionExternalService;
import com.otilm.core.util.SecretLeakProbe;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** A sensitive request refused for a malformed field carries its value nowhere. */
class SensitiveRequestRedactionTest {

    private static final String VALID_PASSPHRASE = "correct horse battery staple";

    private static final String FILE = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});

    private final FileInspectionExternalService fileInspectionService = mock(FileInspectionExternalService.class);
    private final CertificateImportExternalService certificateImportService = mock(
            CertificateImportExternalService.class);
    private final CertificateKeystoreExternalService certificateKeystoreService = mock(
            CertificateKeystoreExternalService.class);
    private final CryptographicKeyImportExternalService cryptographicKeyImportService = mock(
            CryptographicKeyImportExternalService.class);
    private final CryptographicKeyExportExternalService cryptographicKeyExportService = mock(
            CryptographicKeyExportExternalService.class);

    private final InspectionControllerImpl inspectionController = new InspectionControllerImpl();
    private final CertificateControllerImpl certificateController = new CertificateControllerImpl();
    private final CryptographicKeyControllerImpl keyController = new CryptographicKeyControllerImpl();
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        inspectionController.setFileInspectionExternalService(fileInspectionService);
        certificateController.setCertificateImportService(certificateImportService);
        certificateController.setCertificateKeystoreService(certificateKeystoreService);
        keyController.setCryptographicKeyImportExternalService(cryptographicKeyImportService);
        keyController.setCryptographicKeyExportExternalService(cryptographicKeyExportService);
        mvc = MockMvcBuilders
                .standaloneSetup(inspectionController, certificateController, keyController)
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .build();
    }

    static Stream<Arguments> malformedRequests() {
        UUID uuid = UUID.randomUUID();
        return Stream
                .of(arguments(named("inspection, passphrase as a number", "/v1/inspections"),
                        inspection("\"" + FILE + "\"", "314159265358979323846"), "314159265358979323846"),
                        arguments(named("inspection, file not base64", "/v1/inspections"),
                                inspection("\"not base64 !secret-file!\"", "\"" + VALID_PASSPHRASE + "\""),
                                "!secret-file!"),
                        arguments(named("certificate import, passphrase as an object", "/v1/certificates/import"),
                                certificateImport("{\"value\":\"object-secret\"}"), "object-secret"),
                        arguments(named("keystore, passphrase too short", keystorePath(uuid)),
                                "{\"passphrase\":\"shortsecret\"}", "shortsecret"),
                        arguments(named("keystore, passphrase as an array", keystorePath(uuid)),
                                "{\"passphrase\":[\"array-secret\"]}", "array-secret"),
                        arguments(named("key import, passphrase as a number", keyImportPath()),
                                keyImport("271828182845904523536"), "271828182845904523536"),
                        arguments(named("key export, passphrase too short", keyExportPath(uuid)),
                                "{\"passphrase\":\"tiny-secret\",\"exportAttributes\":[]}", "tiny-secret"));
    }

    @ParameterizedTest
    @MethodSource("malformedRequests")
    void aMalformedSensitiveFieldIsRefusedWithoutItsValue(String path, String body, String secret) throws Exception {
        // given
        SecretLeakProbe probe = SecretLeakProbe.capture();
        MockHttpServletResponse response;

        // when
        try (probe) {
            response = mvc
                    .perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body))
                    .andReturn()
                    .getResponse();
        }

        // then
        assertThat(response.getStatus()).isIn(400, 422);
        List<String> seen = new ArrayList<>(probe.logged());
        seen.add(response.getContentAsString());
        SecretLeakProbe.assertNoneReveals(seen, secret);
    }

    @Test
    void inspect_clearsTheFileAndThePassphraseWhenTheServiceRefuses() throws Exception {
        // given
        ArgumentCaptor<InspectionRequestDto> sent = ArgumentCaptor.forClass(InspectionRequestDto.class);
        when(fileInspectionService.inspect(sent.capture())).thenThrow(new ValidationException("refused"));

        // when
        MockHttpServletResponse response = mvc
                .perform(post("/v1/inspections")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"file\":\"" + FILE + "\",\"passphrase\":\"" + VALID_PASSPHRASE + "\"}"))
                .andReturn()
                .getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(422);
        assertThat(sent.getValue().getFile().length()).isZero();
        assertThat(sent.getValue().getPassphrase().codePointLength()).isZero();
    }

    @Test
    void downloadKeystore_clearsThePassphraseWhenTheServiceRefuses() throws Exception {
        // given
        ArgumentCaptor<CertificateKeystoreRequestDto> sent = ArgumentCaptor
                .forClass(CertificateKeystoreRequestDto.class);
        when(certificateKeystoreService.downloadKeystore(any(), sent.capture()))
                .thenThrow(new ValidationException("refused"));

        // when
        MockHttpServletResponse response = mvc
                .perform(post("/v1/certificates/{uuid}/keystore", UUID.randomUUID())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"passphrase\":\"" + VALID_PASSPHRASE + "\"}"))
                .andReturn()
                .getResponse();

        // then
        assertThat(response.getStatus()).isEqualTo(422);
        assertThat(sent.getValue().getPassphrase().codePointLength()).isZero();
    }

    private static String inspection(String fileJson, String passphraseJson) {
        return "{\"file\":" + fileJson + ",\"passphrase\":" + passphraseJson + "}";
    }

    private static String certificateImport(String passphraseJson) {
        return "{\"file\":\"" + FILE + "\",\"passphrase\":" + passphraseJson
                + ",\"entries\":[{\"entryReference\":\"reference-1\"}]}";
    }

    private static String keyImport(String passphraseJson) {
        return "{\"name\":\"imported key\",\"file\":\"" + FILE + "\",\"inputPassphrase\":" + passphraseJson + "}";
    }

    private static String keystorePath(UUID uuid) {
        return "/v1/certificates/" + uuid + "/keystore";
    }

    private static String keyImportPath() {
        return "/v1/tokens/" + UUID.randomUUID() + "/tokenProfiles/" + UUID.randomUUID() + "/keys/"
                + KeyRequestType.KEY_PAIR.getCode() + "/import";
    }

    private static String keyExportPath(UUID uuid) {
        return "/v1/keys/" + uuid + "/items/" + UUID.randomUUID() + "/export";
    }
}
