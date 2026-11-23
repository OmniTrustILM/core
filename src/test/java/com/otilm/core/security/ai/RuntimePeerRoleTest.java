package com.otilm.core.security.ai;

import java.net.InetAddress;
import java.security.cert.CertificateException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import java.util.Set;
import javax.net.ssl.SSLException;
import javax.net.ssl.X509ExtendedKeyManager;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.authorities;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.chain;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.engines;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.handshake;
import static com.otilm.core.security.ai.RuntimeProxyTrustManagerTest.issue;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class RuntimePeerRoleTest {
    private static final String SUBJECT = "://lab/ns/runtime/sa/runner/pod/run-a/uid/27b7adad-1f27-490a-971d-633e8abbdfbd";
    private static final RuntimeProxyCertificateClaims CLAIMS = RuntimeProxyCertificateClaims
            .parse("ilm-runtime-proxy" + SUBJECT)
            .orElseThrow();
    private static final Map<RuntimePeerRole, String> SCHEMES = Map
            .of(RuntimePeerRole.RUNNER_PROXY, "ilm-runtime-proxy", RuntimePeerRole.CONTROLLER, "ilm-runtime-controller",
                    RuntimePeerRole.GATEWAY_RUN, "ilm-runtime-gateway-run", RuntimePeerRole.GATEWAY_MANAGEMENT,
                    "ilm-runtime-gateway-management");
    private static Instant now;
    private static RuntimeProxyTrustManagerTest.Identity authority;
    private static RuntimeProxyTrustManagerTest.Identity server;

    @BeforeAll
    static void identities() throws Exception {
        now = Instant.now();
        authority = issue(null, true, KeyUsage.keyCertSign | KeyUsage.cRLSign, null, null, now.minusSeconds(30),
                now.plusSeconds(900));
        server = issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_serverAuth,
                new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost")), now.minusSeconds(10),
                now.plusSeconds(600));
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void exactRoleProfileRetainsRoleAndSubject(RuntimePeerRole role) {
        String uri = SCHEMES.get(role) + SUBJECT;
        var parsed = role.parseCertificateUri(uri).orElseThrow();
        assertThat(parsed.role()).isEqualTo(role);
        assertThat(parsed.subject()).isEqualTo(CLAIMS);
        assertThat(parsed.certificateUri()).isEqualTo(uri);
        assertThat(role.certificateUri(CLAIMS)).isEqualTo(uri);
        assertThat(parsed.toString()).doesNotContain("run-a", "27b7adad", "runner");
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void otherRolesAndMalformedSubjectAreNotAccepted(RuntimePeerRole role) {
        String uri = SCHEMES.get(role) + SUBJECT;
        for (RuntimePeerRole other : RuntimePeerRole.values()) {
            if (other != role) {
                assertThat(role.parseCertificateUri(SCHEMES.get(other) + SUBJECT)).isEmpty();
            }
        }
        for (String invalid : List
                .of("", "unknown" + SUBJECT, uri.toUpperCase(), uri + "/", uri + "?role=controller", uri + "#fragment",
                        uri.replace("/ns/", "/n%73/"),
                        uri.replace("27b7adad-1f27-490a-971d-633e8abbdfbd", "00000000-0000-0000-0000-000000000000"))) {
            assertThat(role.parseCertificateUri(invalid)).as(invalid).isEmpty();
        }
        assertThat(role.parseCertificateUri(null)).isEmpty();
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void sameCaCannotAuthenticateAnotherRole(RuntimePeerRole expected) throws Exception {
        var manager = manager(expected);
        for (RuntimePeerRole actual : RuntimePeerRole.values()) {
            var client = client(actual);
            if (actual == expected) {
                var peer = manager.verifyWorkloadNativeChain(chain(client, authority));
                assertThat(peer.role()).isEqualTo(expected);
                assertThat(peer.subject()).isEqualTo(CLAIMS);
            } else {
                assertThatThrownBy(() -> manager.verifyWorkloadNativeChain(chain(client, authority)))
                        .isInstanceOf(CertificateException.class)
                        .hasMessage("Runtime proxy certificate rejected")
                        .hasNoCause();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void realMutualTlsSessionPreservesConfiguredRole(RuntimePeerRole role) throws Exception {
        var client = client(role);
        var manager = manager(role);
        try (var connection = engines(authority, client, server, manager, chain(client, authority))) {
            handshake(connection.client(), connection.peer());
            var session = connection.peer().getSession();
            assertThat(session.getProtocol()).isEqualTo("TLSv1.3");
            var peer = manager.verifyWorkloadPeer(session);
            assertThat(peer.role()).isEqualTo(role);
            assertThat(peer.subject()).isEqualTo(CLAIMS);
            if (role == RuntimePeerRole.RUNNER_PROXY) {
                assertThat(manager.verifyPeer(session)).isEqualTo(CLAIMS);
                assertThat(manager.verifyNativeChain(chain(client, authority))).isEqualTo(CLAIMS);
            } else {
                assertThatThrownBy(() -> manager.verifyPeer(session))
                        .isInstanceOf(CertificateException.class)
                        .hasNoCause();
                assertThatThrownBy(() -> manager.verifyNativeChain(chain(client, authority)))
                        .isInstanceOf(CertificateException.class)
                        .hasNoCause();
            }
        }
    }

    @ParameterizedTest
    @EnumSource(RuntimePeerRole.class)
    void realTlsRejectsEveryOtherRoleEvenFromTheSameCa(RuntimePeerRole expected) throws Exception {
        var manager = manager(expected);
        for (RuntimePeerRole actual : RuntimePeerRole.values()) {
            if (actual == expected) {
                continue;
            }
            var client = client(actual);
            try (var connection = engines(authority, client, server, manager, chain(client, authority))) {
                assertThatThrownBy(() -> handshake(connection.client(), connection.peer()))
                        .isInstanceOf(SSLException.class);
            }
        }
    }

    @Test
    void defaultTrustRemainsRunnerOnly() throws Exception {
        var observed = policy();
        var manager = new RuntimeProxyTrustManager(() -> observed, Clock.fixed(now, ZoneOffset.UTC));
        assertThat(manager.verifyNativeChain(chain(client(RuntimePeerRole.RUNNER_PROXY), authority))).isEqualTo(CLAIMS);
        assertThatThrownBy(
                () -> manager.verifyWorkloadNativeChain(chain(client(RuntimePeerRole.GATEWAY_RUN), authority)))
                .isInstanceOf(CertificateException.class)
                .hasNoCause();
    }

    @Test
    void runnerTransportRejectsOtherRoleTrustBeforeInstallation() throws Exception {
        var loopback = InetAddress.getLoopbackAddress();
        var keys = mock(X509ExtendedKeyManager.class);
        for (RuntimePeerRole role : RuntimePeerRole.values()) {
            if (role != RuntimePeerRole.RUNNER_PROXY) {
                assertThatThrownBy(() -> new RuntimeProxyTransport(loopback, 0, "", keys, manager(role)))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasNoCause();
            }
        }
    }

    @Test
    void missingTrustedRoleOrSubjectCannotProduceAPeer() {
        assertThatThrownBy(() -> new RuntimePeer(null, CLAIMS)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RuntimePeer(RuntimePeerRole.RUNNER_PROXY, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new RuntimeProxyTrustManager(() -> policy(), Clock.fixed(now, ZoneOffset.UTC), null))
                .isInstanceOf(NullPointerException.class);
    }

    private static RuntimeProxyTrustManager manager(RuntimePeerRole role) {
        var observed = policy();
        return new RuntimeProxyTrustManager(() -> observed, Clock.fixed(now, ZoneOffset.UTC), role);
    }

    private static RuntimeProxyTrustManager.Policy policy() {
        return new RuntimeProxyTrustManager.Policy(authorities(authority.certificate()), Set.of(), now,
                now.plusSeconds(30));
    }

    private static RuntimeProxyTrustManagerTest.Identity client(RuntimePeerRole role) throws Exception {
        return issue(authority, false, KeyUsage.digitalSignature, KeyPurposeId.id_kp_clientAuth,
                new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, SCHEMES.get(role) + SUBJECT)),
                now.minusSeconds(10), now.plusSeconds(600));
    }
}
