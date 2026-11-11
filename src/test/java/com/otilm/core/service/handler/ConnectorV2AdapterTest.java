package com.otilm.core.service.handler;

import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.signing.contentsigning.ContentSigningFormattingSyncApiClient;
import com.otilm.api.interfaces.client.v2.InfoSyncApiClient;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorInterfaceInfo;
import com.otilm.api.model.client.connector.v2.InfoResponse;
import com.otilm.api.model.connector.signatures.contentsigning.declaration.ContentSigningDeclarationDto;
import com.otilm.api.model.core.connector.v2.ConnectInfoV2;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.repository.ConnectorContentSigningDeclarationRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;

import static com.otilm.core.util.builders.SignatureFamilyDeclarationDtoBuilder.aFamilyDeclaration;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ConnectorV2AdapterTest {

    // validateConnection(ConnectInfo) is a pure check over the supplied answer, so it runs without Spring or mocks.
    private final ConnectorV2Adapter adapter = new ConnectorV2Adapter();

    @Test
    void missingMandatoryInterface_throws() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("missing mandatory interfaces");
    }

    @Test
    void onlyMandatoryCommons_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("functional");
    }

    /** ATTRIBUTES is a common interface, so it must not count toward the functional-interface requirement. */
    @Test
    void commonsWithAttributes_throwsMissingFunctional() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.ATTRIBUTES);
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("functional");
    }

    /** A malformed connector entry with a null interface code must be rejected as a validation error, not NPE. */
    @Test
    void malformedInterfaceWithNullCode_throws() {
        ConnectInfoV2 connectInfo = new ConnectInfoV2();
        connectInfo
                .setInterfaces(List
                        .of(iface(ConnectorInterface.INFO), iface(ConnectorInterface.HEALTH),
                                iface(ConnectorInterface.METRICS), iface(ConnectorInterface.AUTHORITY),
                                new ConnectorInterfaceInfo(null, "2.0", List.of())));
        assertThatThrownBy(() -> adapter.validateConnection(connectInfo))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("no code");
    }

    @Test
    void acceptsAnswer_whenItHasMandatoryAndFunctionalInterfaces() {
        // given
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY);

        // when
        ThrowingCallable validate = () -> adapter.validateConnection(connectInfo);

        // then
        assertThatCode(validate).doesNotThrowAnyException();
    }

    @Test
    void acceptsAnswer_whenItAlsoHasAttributes() {
        // given
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.ATTRIBUTES, ConnectorInterface.AUTHORITY);

        // when
        ThrowingCallable validate = () -> adapter.validateConnection(connectInfo);

        // then
        assertThatCode(validate).doesNotThrowAnyException();
    }

    @Test
    void updateConnectorFunctions_forgetsWhatTheConnectorsProfilesExport() throws Exception {
        // given
        KeyTransferCapabilityWriter capabilities = mock(KeyTransferCapabilityWriter.class);
        adapter.setKeyTransferCapabilityWriter(capabilities);
        adapter.setConnectorInterfaceRepository(mock(ConnectorInterfaceRepository.class));
        adapter.setContentSigningDeclarationRepository(mock(ConnectorContentSigningDeclarationRepository.class));
        Connector connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.CRYPTOGRAPHY);

        // when
        adapter.updateConnectorFunctions(connector, connectInfo);

        // then
        verify(capabilities).forgetForConnector(connector.getUuid());
    }

    @Test
    void checkConnection_fetchesTheDeclaration_whenTheConnectorServesContentSigning() throws Exception {
        // given
        ContentSigningDeclarationDto declared = aFamilyDeclaration().buildDeclaration();
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        ConnectorApiFactory apiFactory = apiFactoryAnswering(connectorInfo,
                infoResponse(ConnectorInterface.CONTENT_SIGNING_FORMATTING), declared);
        adapter.setConnectorApiFactory(apiFactory);

        // when
        ConnectInfoV2 connectInfo = adapter.checkConnection(connectorInfo);

        // then
        assertThat(connectInfo.getContentSigningDeclaration()).isSameAs(declared);
    }

    @ParameterizedTest
    @MethodSource("declarationRouteFaults")
    void checkConnection_reportsAFaultyDeclarationRoute_asAConnectorFault(ConnectorException fault) throws Exception {
        // given
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        ConnectorApiFactory apiFactory = apiFactoryAnswering(connectorInfo,
                infoResponse(ConnectorInterface.CONTENT_SIGNING_FORMATTING), null);
        when(apiFactory.getContentSigningFormattingApiClient(connectorInfo).getDeclaration(connectorInfo))
                .thenThrow(fault);
        adapter.setConnectorApiFactory(apiFactory);

        // when
        ThrowingCallable connect = () -> adapter.checkConnection(connectorInfo);

        // then
        assertThatThrownBy(connect)
                .isExactlyInstanceOf(ConnectorException.class)
                .hasMessageContaining("content-signing declaration")
                .hasCause(fault);
    }

    @Test
    void checkConnection_passesACommunicationFailureThrough() throws Exception {
        // given
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        ConnectorApiFactory apiFactory = apiFactoryAnswering(connectorInfo,
                infoResponse(ConnectorInterface.CONTENT_SIGNING_FORMATTING), null);
        var unreachable = new ConnectorCommunicationException("connection refused", connectorInfo);
        when(apiFactory.getContentSigningFormattingApiClient(connectorInfo).getDeclaration(connectorInfo))
                .thenThrow(unreachable);
        adapter.setConnectorApiFactory(apiFactory);

        // when
        ThrowingCallable connect = () -> adapter.checkConnection(connectorInfo);

        // then
        assertThatThrownBy(connect).isSameAs(unreachable);
    }

    @Test
    void checkConnection_asksForNoDeclaration_whenTheConnectorServesNoContentSigning() throws Exception {
        // given
        ApiClientConnectorInfo connectorInfo = mock(ApiClientConnectorInfo.class);
        ConnectorApiFactory apiFactory = apiFactoryAnswering(connectorInfo, infoResponse(ConnectorInterface.AUTHORITY),
                null);
        adapter.setConnectorApiFactory(apiFactory);

        // when
        ConnectInfoV2 connectInfo = adapter.checkConnection(connectorInfo);

        // then
        assertThat(connectInfo.getContentSigningDeclaration()).isNull();
        verify(apiFactory, never()).getContentSigningFormattingApiClient(connectorInfo);
    }

    @Test
    void refusesAnswer_whenAContentSigningConnectorSendsNoDeclaration() {
        // given
        ConnectInfoV2 connectInfo = contentSigningConnectInfo();
        connectInfo.setContentSigningDeclaration(null);

        // when
        ThrowingCallable validate = () -> adapter.validateConnection(connectInfo);

        // then
        assertThatThrownBy(validate).isInstanceOf(ValidationException.class).hasMessageContaining("declaration");
    }

    @Test
    void updateConnectorFunctions_storesTheDeclaration_whenTheConnectorSendsOne() throws Exception {
        // given
        ConnectorContentSigningDeclarationRepository declarations = wireDeclarations();
        Connector connector = aConnector();
        ConnectInfoV2 connectInfo = contentSigningConnectInfo();

        // when
        adapter.updateConnectorFunctions(connector, connectInfo);

        // then
        verify(declarations)
                .save(argThat(stored -> stored.getConnectorUuid().equals(connector.getUuid())
                        && stored.getDeclaration() == connectInfo.getContentSigningDeclaration()));
    }

    @Test
    void updateConnectorFunctions_forgetsTheDeclaration_whenTheConnectorServesNoContentSigning() throws Exception {
        // given
        ConnectorContentSigningDeclarationRepository declarations = wireDeclarations();
        Connector connector = aConnector();
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.AUTHORITY);
        connectInfo.setContentSigningDeclaration(aFamilyDeclaration().buildDeclaration());

        // when
        adapter.updateConnectorFunctions(connector, connectInfo);

        // then
        verify(declarations).deleteById(connector.getUuid());
    }

    @Test
    void updateConnectorFunctions_failsItsInvariant_whenAnUnvalidatedFormattingAnswerLacksTheDeclaration() {
        // given
        ConnectorContentSigningDeclarationRepository declarations = wireDeclarations();
        Connector connector = aConnector();
        ConnectInfoV2 withoutDeclaration = contentSigningConnectInfo();
        withoutDeclaration.setContentSigningDeclaration(null);

        // when
        ThrowingCallable update = () -> adapter.updateConnectorFunctions(connector, withoutDeclaration);

        // then
        assertThatThrownBy(update)
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("validateConnection refuses");
        verifyNoInteractions(declarations);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ConnectInfoV2 connectInfo(ConnectorInterface... codes) {
        ConnectInfoV2 connectInfo = new ConnectInfoV2();
        connectInfo.setInterfaces(Arrays.stream(codes).map(ConnectorV2AdapterTest::iface).toList());
        return connectInfo;
    }

    private static ConnectorInterfaceInfo iface(ConnectorInterface code) {
        return new ConnectorInterfaceInfo(code, "2.0", List.of());
    }

    private ConnectorContentSigningDeclarationRepository wireDeclarations() {
        ConnectorContentSigningDeclarationRepository declarations = mock(
                ConnectorContentSigningDeclarationRepository.class);
        adapter.setContentSigningDeclarationRepository(declarations);
        adapter.setKeyTransferCapabilityWriter(mock(KeyTransferCapabilityWriter.class));
        adapter.setConnectorInterfaceRepository(mock(ConnectorInterfaceRepository.class));
        return declarations;
    }

    private static Connector aConnector() {
        Connector connector = new Connector();
        connector.setUuid(UUID.randomUUID());
        return connector;
    }

    private static ConnectInfoV2 contentSigningConnectInfo() {
        ConnectInfoV2 connectInfo = connectInfo(ConnectorInterface.INFO, ConnectorInterface.HEALTH,
                ConnectorInterface.METRICS, ConnectorInterface.CONTENT_SIGNING_FORMATTING);
        connectInfo.setContentSigningDeclaration(aFamilyDeclaration().buildDeclaration());
        return connectInfo;
    }

    private static InfoResponse infoResponse(ConnectorInterface functionalInterface) {
        InfoResponse infoResponse = new InfoResponse();
        infoResponse
                .setInterfaces(List
                        .of(iface(ConnectorInterface.INFO), iface(ConnectorInterface.HEALTH),
                                iface(ConnectorInterface.METRICS), iface(functionalInterface)));
        return infoResponse;
    }

    static Stream<ConnectorException> declarationRouteFaults() {
        return Stream
                .of(new ConnectorEntityNotFoundException("declaration not found"),
                        new ConnectorServerException("declaration failed", HttpStatus.INTERNAL_SERVER_ERROR));
    }

    private static ConnectorApiFactory apiFactoryAnswering(ApiClientConnectorInfo connectorInfo,
            InfoResponse infoResponse, ContentSigningDeclarationDto declaration) throws Exception {
        ConnectorApiFactory apiFactory = mock(ConnectorApiFactory.class);
        InfoSyncApiClient infoClient = mock(InfoSyncApiClient.class);
        when(apiFactory.getInfoApiClientV2(connectorInfo)).thenReturn(infoClient);
        when(infoClient.getConnectorInfo(connectorInfo)).thenReturn(infoResponse);
        ContentSigningFormattingSyncApiClient formattingClient = mock(ContentSigningFormattingSyncApiClient.class);
        when(apiFactory.getContentSigningFormattingApiClient(connectorInfo)).thenReturn(formattingClient);
        when(formattingClient.getDeclaration(connectorInfo)).thenReturn(declaration);
        return apiFactory;
    }
}
