package com.otilm.core.util.builders;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.util.MetaDefinitions;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

/**
 * Shared authority-fixture builder for integration tests.
 *
 * <p>Creates the entity graph — Connector (with AUTHORITY_PROVIDER function group),
 * AuthorityInstanceReference, and RaProfile — directly via repositories, without going through
 * the service layer. This makes it usable from any {@code @SpringBootTest} IT class that already
 * starts a WireMock server.
 *
 * <p>Four factory methods are provided:
 * <ul>
 *   <li>{@link #v2Authority(Repos, WireMockServer, String)} — v2 adapter path; connector URL is
 *       bound to the given WireMock server. Use when the test makes connector HTTP calls.</li>
 *   <li>{@link #v2Authority(Repos, String)} — v2 adapter path; connector URL is a unique synthetic
 *       placeholder. Use for tests that inspect v2 capability flags but make no connector calls.</li>
 *   <li>{@link #v3Authority(Repos, WireMockServer, FeatureFlag...)} — v3 adapter path; connector URL
 *       is bound to the given WireMock server. Use when the test makes connector HTTP calls.</li>
 *   <li>{@link #v3Authority(Repos, FeatureFlag...)} — v3 adapter path; connector URL is a unique
 *       synthetic placeholder. Use for tests that inspect v3 capability flags but make no connector
 *       calls.</li>
 * </ul>
 *
 * <p>The synthetic-URL overloads generate a URL of the form
 * {@code "http://localhost/" + UUID.randomUUID()} so that each connector satisfies the
 * {@code uq_connector_url_version} unique index without requiring an extra WireMock server.
 */
public final class AuthorityFixtures {

    private AuthorityFixtures() {}

    /**
     * Repositories required by both factory methods.
     *
     * @param connectorRepository                 persists the Connector
     * @param functionGroupRepository             persists the AUTHORITY_PROVIDER FunctionGroup
     * @param connector2FunctionGroupRepository   persists the Connector-to-FunctionGroup mapping
     * @param authorityInstanceReferenceRepository persists the AuthorityInstanceReference
     * @param raProfileRepository                 persists the RaProfile
     * @param connectorInterfaceRepository        persists the ConnectorInterfaceEntity (v3 only)
     */
    public record Repos(
            ConnectorRepository connectorRepository,
            FunctionGroupRepository functionGroupRepository,
            Connector2FunctionGroupRepository connector2FunctionGroupRepository,
            AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository,
            RaProfileRepository raProfileRepository,
            ConnectorInterfaceRepository connectorInterfaceRepository
    ) {}

    /**
     * Holds the saved entities produced by the factory methods.
     */
    public record Fixture(
            Connector connector,
            AuthorityInstanceReference authority,
            RaProfile raProfile
    ) {}

    /**
     * Builds a v2-adapter authority fixture whose connector URL is bound to the given WireMock server.
     *
     * <p>Use this overload when the test makes real HTTP calls to the connector (e.g. issue, revoke,
     * list-attributes). The resulting {@code Fixture.authority.getConnectorInterface()} is {@code null},
     * meaning the service layer will select the v2 (legacy) adapter path.
     *
     * @param r    repository holder
     * @param wm   WireMock server whose port is used as the connector URL
     * @param kind authority kind label stored on the AuthorityInstanceReference (e.g. "MOCK_EJBCA")
     */
    public static Fixture v2Authority(Repos r, WireMockServer wm, String kind) {
        Connector connector = saveConnector(r, "http://localhost:" + wm.port());
        AuthorityInstanceReference authority = saveAuthority(r, connector, null, kind);
        RaProfile raProfile = saveRaProfile(r, authority);
        return new Fixture(connector, authority, raProfile);
    }

    /**
     * Builds a v2-adapter authority fixture with a unique synthetic connector URL.
     *
     * <p>Use this overload for tests that inspect v2 capability flags or trigger pre-connector
     * rejections but make no HTTP calls to the connector. Each call generates a distinct URL so
     * multiple connectors within one test satisfy the {@code uq_connector_url_version} unique index
     * without requiring an extra WireMock server.
     *
     * <p>The resulting {@code Fixture.authority.getConnectorInterface()} is {@code null},
     * meaning the service layer will select the v2 (legacy) adapter path.
     *
     * @param r    repository holder
     * @param kind authority kind label stored on the AuthorityInstanceReference (e.g. "MOCK_V2")
     */
    public static Fixture v2Authority(Repos r, String kind) {
        Connector connector = saveConnector(r, syntheticUrl());
        AuthorityInstanceReference authority = saveAuthority(r, connector, null, kind);
        RaProfile raProfile = saveRaProfile(r, authority);
        return new Fixture(connector, authority, raProfile);
    }

    /**
     * Builds a v3-adapter authority fixture whose connector URL is bound to the given WireMock server.
     *
     * <p>Use this overload when the test makes real HTTP calls to the connector (e.g. register, cancel,
     * poll). A {@link ConnectorInterfaceEntity} with interface code {@code AUTHORITY}, version {@code "v3"},
     * and the supplied feature flags is saved and bound to the authority reference, causing the service
     * layer to select the v3 adapter.
     *
     * @param r        repository holder
     * @param wm       WireMock server whose port is used as the connector URL
     * @param features feature flags advertised by the authority (e.g. CERTIFICATE_REGISTRATION, CERTIFICATE_STATUS_POLLING)
     */
    public static Fixture v3Authority(Repos r, WireMockServer wm, FeatureFlag... features) {
        Connector connector = saveConnector(r, "http://localhost:" + wm.port());
        ConnectorInterfaceEntity iface = saveConnectorInterface(r, connector, features);
        AuthorityInstanceReference authority = saveAuthority(r, connector, iface, null);
        RaProfile raProfile = saveRaProfile(r, authority);
        return new Fixture(connector, authority, raProfile);
    }

    /**
     * Builds a v3-adapter authority fixture with a unique synthetic connector URL.
     *
     * <p>Use this overload for tests that inspect v3 capability flags or trigger pre-connector
     * rejections but make no HTTP calls to the connector. Each call generates a distinct URL so
     * multiple connectors within one test satisfy the {@code uq_connector_url_version} unique index
     * without requiring an extra WireMock server.
     *
     * <p>A {@link ConnectorInterfaceEntity} with interface code {@code AUTHORITY}, version {@code "v3"},
     * and the supplied feature flags is saved and bound to the authority reference, causing the service
     * layer to select the v3 adapter.
     *
     * @param r        repository holder
     * @param features feature flags advertised by the authority (e.g. CERTIFICATE_REGISTRATION, CERTIFICATE_STATUS_POLLING)
     */
    public static Fixture v3Authority(Repos r, FeatureFlag... features) {
        Connector connector = saveConnector(r, syntheticUrl());
        ConnectorInterfaceEntity iface = saveConnectorInterface(r, connector, features);
        AuthorityInstanceReference authority = saveAuthority(r, connector, iface, null);
        RaProfile raProfile = saveRaProfile(r, authority);
        return new Fixture(connector, authority, raProfile);
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /** Returns a URL that is unique per call and will never receive real HTTP traffic. */
    private static String syntheticUrl() {
        return "http://localhost/" + UUID.randomUUID();
    }

    private static Connector saveConnector(Repos r, String url) {
        Connector connector = new Connector();
        connector.setName("testConnector-" + UUID.randomUUID());
        connector.setUrl(url);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector.setVersion(ConnectorVersion.V2);
        connector = r.connectorRepository().save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        r.functionGroupRepository().save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of()));
        r.connector2FunctionGroupRepository().save(c2fg);

        connector.getFunctionGroups().add(c2fg);
        return r.connectorRepository().save(connector);
    }

    private static ConnectorInterfaceEntity saveConnectorInterface(Repos r, Connector connector, FeatureFlag[] features) {
        ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
        iface.setConnectorUuid(connector.getUuid());
        iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
        iface.setVersion("v3");
        iface.setFeatures(features == null || features.length == 0
                ? List.of()
                : Arrays.asList(features));
        return r.connectorInterfaceRepository().save(iface);
    }

    private static AuthorityInstanceReference saveAuthority(Repos r, Connector connector, ConnectorInterfaceEntity iface, String kind) {
        AuthorityInstanceReference authority = new AuthorityInstanceReference();
        authority.setAuthorityInstanceUuid(UUID.randomUUID().toString());
        authority.setName("testAuthority-" + UUID.randomUUID());
        authority.setStatus("connected");
        authority.setConnector(connector);
        authority.setConnectorName(connector.getName());
        if (kind != null) {
            authority.setKind(kind);
        }
        if (iface != null) {
            authority.setConnectorInterface(iface);
        }
        return r.authorityInstanceReferenceRepository().save(authority);
    }

    private static RaProfile saveRaProfile(Repos r, AuthorityInstanceReference authority) {
        RaProfile raProfile = new RaProfile();
        raProfile.setName("testRaProfile-" + UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authority);
        raProfile.setAuthorityInstanceReferenceUuid(authority.getUuid());
        raProfile.setEnabled(true);
        return r.raProfileRepository().save(raProfile);
    }
}
