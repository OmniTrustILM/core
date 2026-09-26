package com.otilm.core.service.handler.key;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v2.CryptographicOperationsSyncApiClient;
import com.otilm.api.interfaces.client.v2.KeySyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import com.otilm.api.model.connector.common.v2.OperationExecutionMode;
import com.otilm.api.model.connector.common.v2.OperationStatus;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.OperationResponseValidator;
import com.otilm.api.model.connector.cryptography.v2.OperationTrackingRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ImportKeyResultRequestV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairOperationStatusResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.secrets.content.ApiKeySecretContent;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.OutboundSecretContainment;
import com.otilm.core.attribute.engine.OutboundSecretLeakException;
import com.otilm.core.client.CryptographyV2ApiClients;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.key.normalization.NormalizedKey;
import com.otilm.core.model.connector.ImmutableConnectorFullModel;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyImportAttempt;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.service.handler.ConnectorCapabilityService;
import com.otilm.core.service.handler.OperationAttributeResolver;
import jakarta.validation.Validation;
import java.io.IOException;
import java.security.KeyPairGenerator;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.groups.Tuple.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class KeyProviderV2AdapterImportTest {

    private static final char[] TRANSPORT_PASSPHRASE = "transport-passphrase-of-forty-three-chars-x".toCharArray();

    private KeySyncApiClient client;
    private OperationAttributeResolver resolver;
    private UUID connectorUuid;
    private ImmutableConnectorFullModel connector;
    private KeyProviderV2Adapter adapter;
    private byte[] publicKeySpki;
    private byte[] envelope;

    @BeforeEach
    void setUp() throws Exception {
        connectorUuid = UUID.randomUUID();
        connector = new ImmutableConnectorFullModel(connectorUuid, "connector", ConnectorVersion.V2,
                "http://connector.test", null, List.of(), ConnectorStatus.CONNECTED, null, List.of(), List.of());
        CryptographyV2ApiClients apiClients = mock(CryptographyV2ApiClients.class);
        AttributeEngine attributes = mock(AttributeEngine.class);
        resolver = mock(OperationAttributeResolver.class);
        client = mock(KeySyncApiClient.class);
        when(apiClients.getKeyManagementApiClient(connector)).thenReturn(client);
        CryptographicOperationsSyncApiClient operations = mock(CryptographicOperationsSyncApiClient.class);
        when(apiClients.getCryptographicOperationsApiClient(connector)).thenReturn(operations);
        when(attributes.getRequestObjectDataAttributesContent(any())).thenReturn(List.of());
        when(resolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of())).thenReturn(List.of());
        adapter = new KeyProviderV2Adapter(apiClients, connector, attributes, resolver,
                new OutboundSecretContainment(new ObjectMapper()), new ConnectorCapabilityService(),
                new OperationResponseValidator(Validation.buildDefaultValidatorFactory().getValidator()));
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        publicKeySpki = generator.generateKeyPair().getPublic().getEncoded();
        envelope = new byte[]{1, 2, 3};
    }

    @Test
    void importKey_sendsTheEnvelopeUnderTheAttemptsIdentifiers() throws Exception {
        // given
        KeyImportAttempt attempt = attempt();
        ArgumentCaptor<ImportKeyRequestV2Dto> sent = ArgumentCaptor.forClass(ImportKeyRequestV2Dto.class);
        when(client.importKey(eq(connector), sent.capture())).thenReturn(ResponseEntity.ok(imported()));

        // when
        adapter.importKey(terms(List.of(FeatureFlag.KEY_IMPORT), true), attempt, normalizedKey(), "signing key");

        // then
        ImportKeyRequestV2Dto request = sent.getValue();
        assertThat(request.getKeyImportId()).isEqualTo(attempt.uuid().toString());
        assertThat(request.getKeyReference()).isEqualTo(attempt.keyReference().toString());
        assertThat(request.getKeyRequestType()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(request.getExecutionMode()).isEqualTo(OperationExecutionMode.SYNCHRONOUS);
        assertThat(request.getMaterial().getEncryptedPrivateKeyInfo()).isEqualTo(envelope);
        assertThat(request.getPassphrase()).isEqualTo(new String(TRANSPORT_PASSPHRASE));
        assertThat(request.getExportable()).isTrue();
        assertThat(request.getImportKeyAttributes()).isEmpty();
        assertThat(request.getTokenAttributes()).isEmpty();
        assertThat(request.getTokenProfileAttributes()).isEmpty();
    }

    @Test
    void importKey_describesTheKeyTheConnectorImported() throws Exception {
        // given
        when(client.importKey(eq(connector), any())).thenReturn(ResponseEntity.ok(imported()));

        // when
        ImportAnswer answer = adapter
                .importKey(terms(List.of(FeatureFlag.KEY_IMPORT), false), attempt(), normalizedKey(), "signing key");

        // then
        ImportAnswer.Imported imported = (ImportAnswer.Imported) answer;
        assertThat(imported.type()).isEqualTo(KeyRequestType.KEY_PAIR);
        assertThat(imported.publicKey()).isEqualTo(Base64.getEncoder().encodeToString(publicKeySpki));
        assertThat(imported.items())
                .extracting(ProviderKeyItem::name, ProviderKeyItem::type)
                .containsExactly(tuple("signing key public key", KeyType.PUBLIC_KEY),
                        tuple("signing key private key", KeyType.PRIVATE_KEY));
        RemoteKeyReference.MetadataReference privateHandle = (RemoteKeyReference.MetadataReference) imported
                .items()
                .get(1)
                .reference();
        assertThat(privateHandle.keyMeta()).extracting(MetadataAttribute::getName).containsExactly("private-handle");
    }

    @Test
    void importKey_asksAnAsynchronousConnectorForAnAsynchronousImport() throws Exception {
        // given
        ArgumentCaptor<ImportKeyRequestV2Dto> sent = ArgumentCaptor.forClass(ImportKeyRequestV2Dto.class);
        KeyPairDataResponseV2Dto accepted = new KeyPairDataResponseV2Dto();
        accepted.setOperationMeta(metadata("operation"));
        when(client.importKey(eq(connector), sent.capture()))
                .thenReturn(ResponseEntity.status(HttpStatus.ACCEPTED).body(accepted));

        // when
        ImportAnswer answer = adapter
                .importKey(terms(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS), false), attempt(),
                        normalizedKey(), "signing key");

        // then
        assertThat(sent.getValue().getExecutionMode()).isEqualTo(OperationExecutionMode.ASYNCHRONOUS);
        assertThat(((ImportAnswer.Running) answer).operationMeta())
                .extracting(MetadataAttribute::getName)
                .containsExactly("operation");
    }

    @Test
    void importKey_namesOnlyTheCodeOfARefusal() throws Exception {
        // given
        when(client.importKey(eq(connector), any()))
                .thenThrow(new ConnectorProblemException(ProblemDetailExtended
                        .fromErrorCode(ErrorCode.KEY_DECRYPTION_FAILED, "refused " + new String(TRANSPORT_PASSPHRASE),
                                null, null)));

        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("The connector refused to import the key (KEY_DECRYPTION_FAILED).")
                .hasMessageNotContaining(new String(TRANSPORT_PASSPHRASE));
    }

    /** Core never reuses an import identifier with other terms, so the connector holds an import under it. */
    @Test
    void importKey_doesNotTakeATakenIdentifierForARefusal() throws Exception {
        // given
        when(client.importKey(eq(connector), any()))
                .thenThrow(new ConnectorProblemException(
                        ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_ALREADY_EXISTS, "taken", null, null)));

        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage("The connector failed to import the key.");
    }

    @Test
    void importKey_reportsAnyOtherFailureInThePlatformsWords() throws Exception {
        // given
        when(client.importKey(eq(connector), any()))
                .thenThrow(new ConnectorCommunicationException("unreachable " + new String(TRANSPORT_PASSPHRASE),
                        new IOException("down"), connector));

        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage("The connector failed to import the key.");
    }

    @Test
    void importKey_refusesAnAnswerThatEchoesThePassphrase() throws Exception {
        // given
        when(client.importKey(eq(connector), any())).thenAnswer(invocation -> {
            ImportKeyRequestV2Dto request = invocation.getArgument(1);
            KeyPairDataResponseV2Dto answer = imported();
            answer.getPublicKeyData().setKeyMeta(metadata(request.getPassphrase()));
            return ResponseEntity.ok(answer);
        });

        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    /** An answer may not carry what an earlier send of the attempt carried, which is known by its digest only. */
    @Test
    void importKey_refusesAnAnswerThatEchoesWhatAnEarlierSendCarried() throws Exception {
        // given
        when(client.importKey(eq(connector), any())).thenAnswer(invocation -> {
            KeyPairDataResponseV2Dto answer = imported();
            answer.getPublicKeyData().setKeyMeta(metadata("earlier-transport-passphrase"));
            return ResponseEntity.ok(answer);
        });
        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt resent = new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED,
                null, OffsetDateTime.now(),
                OutboundSecretContainment.digestsOf(Set.of("earlier-transport-passphrase")));
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, resent, key, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    @Test
    void importKey_reportsAnAnswerWithoutABodyAsAFailure() throws Exception {
        // given
        when(client.importKey(eq(connector), any())).thenReturn(ResponseEntity.ok().build());
        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage("The connector failed to import the key.");
    }

    @Test
    void importKey_refusesAnAnswerThatEchoesTheEnvelope() throws Exception {
        // given
        KeyPairDataResponseV2Dto accepted = new KeyPairDataResponseV2Dto();
        accepted.setOperationMeta(metadata(Base64.getEncoder().encodeToString(envelope)));
        when(client.importKey(eq(connector), any()))
                .thenReturn(ResponseEntity.status(HttpStatus.ACCEPTED).body(accepted));
        KeyImportTerms terms = terms(List.of(FeatureFlag.KEY_IMPORT, FeatureFlag.ASYNCHRONOUS), false);
        KeyImportAttempt attempt = attempt();
        NormalizedKey key = normalizedKey();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKey(terms, attempt, key, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    @Test
    void importKeyStatus_refusesAnAnswerThatEchoesTheTransportPassphrase() throws Exception {
        // given
        KeyPairDataResponseV2Dto result = imported();
        result.getPublicKeyData().setKeyMeta(metadata(new String(TRANSPORT_PASSPHRASE)));
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(result);
        when(client.getImportKeyStatus(eq(connector), any())).thenReturn(answer);
        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));
        List<MetadataAttribute> handle = metadata("operation");
        List<String> sent = sentSecretDigests();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKeyStatus(profile, handle, sent, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    /** A completed import is described by its status answer, which is stored, so it may carry no token credential. */
    @Test
    void importKeyStatus_refusesACompletedAnswerThatEchoesATokenCredential() throws Exception {
        // given
        when(resolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of()))
                .thenReturn(credential("token-credential"), List.of());
        KeyPairDataResponseV2Dto result = imported();
        result.getPublicKeyData().setKeyMeta(metadata("token-credential"));
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(result);
        when(client.getImportKeyStatus(eq(connector), any())).thenReturn(answer);
        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));
        List<MetadataAttribute> handle = metadata("operation");
        List<String> sent = sentSecretDigests();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKeyStatus(profile, handle, sent, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    @Test
    void importKeyResult_refusesAnAnswerThatEchoesAProfileCredential() throws Exception {
        // given
        when(resolver.resolveForConnectorRequestAsSystem(connectorUuid, List.of()))
                .thenReturn(List.of(), credential("profile-credential"));
        KeyPairDataResponseV2Dto result = imported();
        result.getPrivateKeyData().setKeyMeta(metadata("profile-credential"));
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(result);
        when(client.getImportKeyResult(eq(connector), any())).thenReturn(answer);
        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));
        UUID keyImportId = UUID.randomUUID();
        List<String> sent = sentSecretDigests();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKeyResult(profile, keyImportId, sent, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    @Test
    void importKeyResult_refusesAnAnswerThatEchoesTheEnvelope() throws Exception {
        // given
        KeyPairDataResponseV2Dto result = imported();
        result.getPrivateKeyData().setKeyMeta(metadata(Base64.getEncoder().encodeToString(envelope)));
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(result);
        when(client.getImportKeyResult(eq(connector), any())).thenReturn(answer);
        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));
        UUID keyImportId = UUID.randomUUID();
        List<String> sent = sentSecretDigests();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKeyResult(profile, keyImportId, sent, "key"))
                .isInstanceOf(OutboundSecretLeakException.class);
    }

    @ParameterizedTest
    @EnumSource(value = OperationStatus.class, names = {"FAILED", "CANCELLED"})
    void importKeyStatus_readsAnEndWithoutAKeyAsNothingImported(OperationStatus status) throws Exception {
        // given
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(status);
        answer.setReason("stopped");
        when(client.getImportKeyStatus(eq(connector), any())).thenReturn(answer);

        // when
        ImportAnswer read = adapter
                .importKeyStatus(profile(List.of(FeatureFlag.KEY_IMPORT)), metadata("operation"), sentSecretDigests(),
                        "key");

        // then
        assertThat(read).isEqualTo(new ImportAnswer.NotImported());
    }

    @Test
    void importKeyStatus_keepsTheHandleOfAnImportStillRunning() throws Exception {
        // given
        List<MetadataAttribute> handle = metadata("operation");
        ArgumentCaptor<OperationTrackingRequestV2Dto> sent = ArgumentCaptor
                .forClass(OperationTrackingRequestV2Dto.class);
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.IN_PROGRESS);
        when(client.getImportKeyStatus(eq(connector), sent.capture())).thenReturn(answer);

        // when
        ImportAnswer read = adapter
                .importKeyStatus(profile(List.of(FeatureFlag.KEY_IMPORT)), handle, sentSecretDigests(), "key");

        // then
        assertThat(sent.getValue().getOperationMeta()).isSameAs(handle);
        assertThat(((ImportAnswer.Running) read).operationMeta()).isSameAs(handle);
    }

    @Test
    void importKeyStatus_describesTheKeyOfACompletedImport() throws Exception {
        // given
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.COMPLETED);
        answer.setResult(imported());
        when(client.getImportKeyStatus(eq(connector), any())).thenReturn(answer);

        // when
        ImportAnswer read = adapter
                .importKeyStatus(profile(List.of(FeatureFlag.KEY_IMPORT)), metadata("operation"), sentSecretDigests(),
                        "key");

        // then
        assertThat(((ImportAnswer.Imported) read).publicKey())
                .isEqualTo(Base64.getEncoder().encodeToString(publicKeySpki));
    }

    @Test
    void importKeyStatus_reportsAFailedQuestionInThePlatformsWords() throws Exception {
        // given
        when(client.getImportKeyStatus(eq(connector), any()))
                .thenThrow(new ConnectorProblemException(
                        ProblemDetailExtended.fromErrorCode(ErrorCode.OPERATION_NOT_TRACKED, "lost", null, null)));

        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));
        List<MetadataAttribute> handle = metadata("operation");
        List<String> sent = sentSecretDigests();

        // when
        // then
        assertThatThrownBy(() -> adapter.importKeyStatus(profile, handle, sent, "key"))
                .isInstanceOf(ConnectorServerException.class)
                .hasMessage("The connector failed to report on the key import.");
    }

    @Test
    void importKeyResult_asksByTheImportIdentifierWithTheTokenScope() throws Exception {
        // given
        UUID keyImportId = UUID.randomUUID();
        ArgumentCaptor<ImportKeyResultRequestV2Dto> sent = ArgumentCaptor.forClass(ImportKeyResultRequestV2Dto.class);
        KeyPairOperationStatusResponseV2Dto answer = new KeyPairOperationStatusResponseV2Dto();
        answer.setStatus(OperationStatus.IN_PROGRESS);
        when(client.getImportKeyResult(eq(connector), sent.capture())).thenReturn(answer);

        // when
        ImportAnswer read = adapter
                .importKeyResult(profile(List.of(FeatureFlag.KEY_IMPORT)), keyImportId, sentSecretDigests(), "key");

        // then
        assertThat(sent.getValue().getKeyImportId()).isEqualTo(keyImportId.toString());
        assertThat(sent.getValue().getTokenAttributes()).isEmpty();
        assertThat(read).isEqualTo(new ImportAnswer.Running(null));
    }

    @Test
    void importKeyResult_readsANotFoundAsNeverAccepted() throws Exception {
        // given
        when(client.getImportKeyResult(eq(connector), any()))
                .thenThrow(new ConnectorProblemException(
                        ProblemDetailExtended.fromErrorCode(ErrorCode.OPERATION_NOT_TRACKED, "never", null, null)))
                .thenThrow(new ConnectorEntityNotFoundException("never"));
        ImmutableTokenProfileFullModel profile = profile(List.of(FeatureFlag.KEY_IMPORT));

        // when
        ImportAnswer problem = adapter.importKeyResult(profile, UUID.randomUUID(), sentSecretDigests(), "key");
        ImportAnswer legacy = adapter.importKeyResult(profile, UUID.randomUUID(), sentSecretDigests(), "key");

        // then
        assertThat(List.of(problem, legacy)).containsOnly(new ImportAnswer.NotAccepted());
    }

    @Test
    void cancelImportKey_isTrueOnlyWhenTheConnectorAbortedTheImport() throws Exception {
        // given
        when(client.cancelImportKey(eq(connector), any()))
                .thenReturn(ResponseEntity.noContent().build())
                .thenThrow(new ConnectorProblemException(ProblemDetailExtended
                        .fromErrorCode(ErrorCode.OPERATION_PAST_POINT_OF_NO_RETURN, "too late", null, null)));

        // when
        boolean aborted = adapter.cancelImportKey(metadata("operation"));
        boolean tooLate = adapter.cancelImportKey(metadata("operation"));

        // then
        assertThat(aborted).isTrue();
        assertThat(tooLate).isFalse();
        verify(client, times(2)).cancelImportKey(eq(connector), any());
    }

    @ParameterizedTest
    @ValueSource(ints = {200, 202})
    void cancelImportKey_takesOnlyA204ForAnAbortedImport(int status) throws Exception {
        // given
        when(client.cancelImportKey(eq(connector), any())).thenReturn(ResponseEntity.status(status).build());

        // when
        boolean aborted = adapter.cancelImportKey(metadata("operation"));

        // then
        assertThat(aborted).isFalse();
    }

    // ---- fixtures ----

    private KeyImportTerms terms(List<FeatureFlag> features, boolean exportable) {
        return new KeyImportTerms(profile(features), KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA, "fingerprint",
                exportable, List.of(), new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
    }

    private ImmutableTokenProfileFullModel profile(List<FeatureFlag> features) {
        ImmutableConnectorInterface cryptography = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", features);
        ImmutableTokenInstanceFullModel token = new ImmutableTokenInstanceFullModel(UUID.randomUUID(), null, "token",
                TokenInstanceStatus.ACTIVATED, "SOFT", connector.uuid(), connector.name(), cryptography.uuid(),
                cryptography, Set.of());
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "profile", null, token.name(), token.uuid(), true,
                List.of(KeyUsage.SIGN), token, connector.uuid(), Map.of(), Map.of(), 0);
    }

    private KeyImportAttempt attempt() {
        return new KeyImportAttempt(UUID.randomUUID(), UUID.randomUUID(), KeyImportState.REQUESTED, null,
                OffsetDateTime.now(), sentSecretDigests());
    }

    private NormalizedKey normalizedKey() {
        return new NormalizedKey(KeyAlgorithm.RSA, publicKeySpki, envelope, new Passphrase(TRANSPORT_PASSPHRASE));
    }

    /** A resolved attribute carrying a secret, as a token or profile credential reaches the adapter. */
    private static List<RequestAttribute> credential(String secret) {
        ResourceObjectContent content = new ResourceObjectContent();
        content.setData(new ResourceSecretContentData("credential", "credential", new ApiKeySecretContent(secret)));
        return List
                .of(new RequestAttributeV3(UUID.randomUUID(), "credential", AttributeContentType.RESOURCE,
                        List.<BaseAttributeContentV3<?>>of(content)));
    }

    /** What an attempt keeps of the secrets it was sent with. */
    private List<String> sentSecretDigests() {
        return OutboundSecretContainment.digestsOf(normalizedKey().transportSecrets());
    }

    private KeyPairDataResponseV2Dto imported() {
        PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
        publicData.setAlgorithm(KeyAlgorithm.RSA);
        publicData.setLength(2048);
        publicData.setPublicKeySpki(publicKeySpki);
        publicData.setMetadata(List.of());
        PublicKeyDataResponseV2Dto publicKey = new PublicKeyDataResponseV2Dto();
        publicKey.setKeyData(publicData);
        publicKey.setKeyMeta(metadata("public-handle"));
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(KeyAlgorithm.RSA);
        privateData.setLength(2048);
        privateData.setMetadata(List.of());
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyData(privateData);
        privateKey.setKeyMeta(metadata("private-handle"));
        KeyPairDataResponseV2Dto answer = new KeyPairDataResponseV2Dto();
        answer.setPublicKeyData(publicKey);
        answer.setPrivateKeyData(privateKey);
        answer.setKeyPairMeta(metadata("pair-handle"));
        return answer;
    }

    private static List<MetadataAttribute> metadata(String name) {
        MetadataAttributeV2 attribute = new MetadataAttributeV2();
        attribute.setName(name);
        return List.of(attribute);
    }
}
