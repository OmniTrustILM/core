package com.otilm.core.integration.ai;

import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.feasibility.ConversationStreamAuthorization;
import com.otilm.core.feasibility.ConversationStreamHttp;
import com.otilm.core.feasibility.ConversationStreamHttpProofConfiguration;
import com.otilm.core.feasibility.ConversationStreamHttpSyntheticAuthConfiguration;
import com.otilm.core.feasibility.ConversationTimeline;
import com.otilm.core.security.authn.ForwardedCertificateFixtures;
import com.otilm.core.security.authn.client.AuthenticationCache;
import com.otilm.core.util.ai.ConversationStreamHttpProofSupport;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import org.apache.coyote.AbstractProtocol;
import org.apache.tomcat.util.net.NioChannel;
import org.apache.tomcat.util.net.NioEndpoint;
import org.apache.tomcat.util.net.SocketWrapperBase;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.core.env.Environment;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;

@Timeout(25)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({ConversationStreamHttpProofConfiguration.class, ConversationStreamHttpSyntheticAuthConfiguration.class})
@TestPropertySource(properties = {
        "server.address=127.0.0.1",
        "server.servlet.context-path=/api",
        "server.ssl.certificate-header-name=X-APP-CERTIFICATE",
        "spring.mvc.async.request-timeout=20s"})
class ConversationStreamHttpITest extends ConversationStreamHttpProofSupport {
    @LocalServerPort
    private int port;
    @Autowired
    private JdbcTemplate jdbc;
    @Autowired
    private AuthenticationCache authenticationCache;
    @Autowired
    private CertificateRepository certificates;
    @Autowired
    private RaProfileRepository profiles;
    @Autowired
    private ConversationStreamHttp handler;
    @Autowired
    private ConversationStreamAuthorization authorization;
    @Autowired
    private WebServerApplicationContext webContext;
    @Autowired
    private ConversationTimeline timeline;
    @Autowired
    private Environment environment;
    private final HttpClient http = HttpClient
            .newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(Duration.ofSeconds(2))
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();
    private UUID conversation;
    private UUID profile;
    private UUID first;
    private UUID second;

    @BeforeEach
    void seedHttpConversation() throws Exception {
        handler.beforeLeaseRelease(() -> {
        });
        handler.resetObservations();
        handler.beforeRead(() -> {
        });
        handler.beforeEmit(() -> {
        });
        authorization.beforeInvocation(() -> {
        });
        AUTHORITY.reset();
        authenticationCache.evictAll();
        authorizationCache.evictAll();
        GATEWAY.reset();
        jdbc
                .execute("TRUNCATE f07_proof.timeline_event, f07_proof.command_record, f07_proof.run_record, "
                        + "f07_proof.retained_certificate, f07_proof.conversation");
        RaProfile ra = new RaProfile();
        ra.setName("Synthetic F07 HTTP " + UUID.randomUUID());
        ra.setEnabled(true);
        ra.setValidationEnabled(false);
        profile = profiles.saveAndFlush(ra).getUuid();
        first = certificate();
        second = certificate();
        conversation = UUID.randomUUID();
        jdbc
                .update("INSERT INTO f07_proof.conversation VALUES (?,?,?,1,0,?,NULL)", conversation, ACTOR, profile,
                        "synthetic HTTP title");
        jdbc.update("INSERT INTO f07_proof.retained_certificate VALUES (?,?)", conversation, first);
        allow(Set.of(first, second));
    }

    @Test
    void ordinaryCertificateFilterAuthenticatesBeforeProtectedTimelineResponse() throws Exception {
        assertThat(environment.getProperty("auth-service.base-url")).isEqualTo(GATEWAY.url());
        assertThat(ReflectionTestUtils.getField(authenticationClient, "customAuthServiceBaseUrl"))
                .isEqualTo(GATEWAY.url());
        var response = http
                .send(request("timeline")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(GATEWAY.certificateRequests()).isEqualTo(1);
        assertThat(handler.lastAuthenticationMethod()).isEqualTo(AuthMethod.CERTIFICATE);
        assertThat(handler.lastActor()).isEqualTo(ACTOR);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(response.body()).path("title").asText()).isEqualTo("synthetic HTTP title");
        assertThat(JSON.readTree(response.body()).path("entries")).isEmpty();
        assertThat(GATEWAY.authoritativeRequests()).isPositive();
        assertThat(AUTHORITY.count("/v1/data/method")).isEqualTo(2);
    }

    @Test
    void missingCredentialAndActorSpoofHeadersCannotAuthenticate() throws Exception {
        var response = http
                .send(request("timeline")
                        .header("X-User-UUID", ACTOR.toString())
                        .header("X-Allow", "true")
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).doesNotContain("synthetic HTTP title");
        assertThat(GATEWAY.deniedRequests()).isEqualTo(1);
    }

    @Test
    void differentActualParsedCertificateIsRejectedByAuthority() throws Exception {
        var response = http
                .send(request("timeline")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.ISSUER_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.body()).doesNotContain("synthetic HTTP title");
        assertThat(GATEWAY.deniedRequests()).isEqualTo(1);
    }

    @Test
    void commandsReplayTheSameRunAndCancellationReportsCommittedTruth() throws Exception {
        byte[] body = "synthetic HTTP command".getBytes(StandardCharsets.UTF_8);
        var created = post("runs", "first-http-command", body);
        assertThat(created.statusCode()).isEqualTo(202);
        UUID run = UUID.fromString(JSON.readTree(created.body()).path("runId").asText());
        assertThat(JSON.readTree(created.body()).path("state").asText()).isEqualTo("QUEUED");
        var replay = post("runs", "first-http-command", body);
        assertThat(replay.statusCode()).isEqualTo(202);
        assertThat(JSON.readTree(replay.body()).path("runId").asText()).isEqualTo(run.toString());
        assertThat(JSON.readTree(replay.body()).path("replay").asBoolean()).isTrue();
        assertThat(post("runs", "first-http-command", new byte[]{1}).statusCode()).isEqualTo(409);
        assertThat(post("follow-ups", "while-active", body).statusCode()).isEqualTo(409);
        var cancelled = post("runs/" + run + "/cancel", "cancel-http-command", body);
        assertThat(cancelled.statusCode()).isEqualTo(202);
        assertThat(JSON.readTree(cancelled.body()).path("state").asText()).isEqualTo("CANCELLED");
        var next = post("follow-ups", "next-http-command", body);
        assertThat(next.statusCode()).isEqualTo(202);
        assertThat(JSON.readTree(next.body()).path("runId").asText()).isNotEqualTo(run.toString());
        var poll = get("timeline", null);
        assertThat(poll.statusCode()).isEqualTo(200);
        assertThat(JSON.readTree(poll.body()).path("run").path("runId").asText())
                .isEqualTo(JSON.readTree(next.body()).path("runId").asText());
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.run_record", Long.class)).isEqualTo(2);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.command_record", Long.class)).isEqualTo(3);
    }

    @Test
    void authorizedForeignExpiredAndUnknownCursorsAreIndistinguishable() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "cursor-run");
        var expired = timeline.append(conversation, run, "expired HTTP canary", Set.of(first), Instant.EPOCH);
        UUID foreign = foreignConversation();
        UUID foreignRun = storedRun(foreign, UUID.fromString("00000000-0000-4000-8000-000000000072"), "foreign-run");
        var hidden = timeline
                .append(foreign, foreignRun, "foreign HTTP canary", Set.of(first),
                        Instant.parse("2100-01-01T00:00:00Z"));
        for (String suffix : List.of("timeline", "events")) {
            var a = get(suffix, expired.cursor().toString());
            var b = get(suffix, UUID.randomUUID().toString());
            var c = get(suffix, hidden.cursor().toString());
            assertThat(a.statusCode()).isEqualTo(410);
            assertThat(b.statusCode()).isEqualTo(410);
            assertThat(c.statusCode()).isEqualTo(410);
            assertThat(a.body())
                    .isEqualTo(b.body())
                    .isEqualTo(c.body())
                    .doesNotContain("synthetic HTTP title", "expired HTTP canary", "foreign HTTP canary");
        }
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.run_record", Long.class)).isEqualTo(2);
    }

    @Test
    void authenticatedForeignAudienceIsDeniedBeforeMalformedCursor() throws Exception {
        UUID foreign = foreignConversation();
        var response = http
                .send(request(foreign, "timeline")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .header("Last-Event-ID", "not-a-cursor")
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).doesNotContain("foreign HTTP title", "synthetic HTTP title", "count", "entries");
    }

    @Test
    void completedSseFramesEscapeHostileTextAndResumeWithoutCreatingRun() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "sse-run");
        String value = "český stream\r\nevent: forged\nid: forged\n<svg onload=alert(1)>";
        var event = timeline.append(conversation, run, value, Set.of(first), Instant.parse("2100-01-01T00:00:00Z"));
        timeline.complete(run);
        HttpResponse<String> response;
        try {
            response = get("events", null);
        } catch (java.io.IOException failure) {
            var probe = handler.completedProbe();
            throw new AssertionError("SSE lifecycle diagnostic: end=" + (probe == null ? "ABSENT" : probe.end)
                    + ", workers=" + handler.activeWorkers() + ", reservations=" + handler.activeReaders());
        }
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Content-Type").orElseThrow()).startsWith("text/event-stream");
        assertThat(response.headers().firstValue("Cache-Control").orElseThrow()).contains("no-store");
        assertThat(response.body())
                .contains("id: " + event.cursor() + "\n", "event: entry\n", "event: complete\ndata:\n\n")
                .doesNotContain("\nevent: forged\n", "\nid: forged\n");
        String data = response
                .body()
                .lines()
                .filter(line -> line.startsWith("data: "))
                .findFirst()
                .orElseThrow()
                .substring(6);
        assertThat(JSON.readTree(data).path("value").asText()).isEqualTo(value);
        assertThat(JSON.readTree(data).path("runId").asText()).isEqualTo(run.toString());
        var resumed = get("events", event.cursor().toString());
        assertThat(resumed.statusCode()).isEqualTo(200);
        assertThat(resumed.body()).contains("event: complete\ndata:\n\n").doesNotContain("event: entry\n");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.run_record", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.command_record", Long.class)).isEqualTo(1);
    }

    @Test
    void escapedOversizeEntryNeverEscapesTheFrameBound() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "oversize-frame-run");
        timeline.append(conversation, run, "\\".repeat(30000), Set.of(first), Instant.parse("2100-01-01T00:00:00Z"));
        timeline.complete(run);
        var response = get("events", null);
        assertThat(response.statusCode()).isIn(200, 500);
        assertThat(response.body().getBytes(StandardCharsets.UTF_8)).hasSizeLessThanOrEqualTo(32768);
        assertThat(response.body()).doesNotContain("event: entry\n", "event: complete\n");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.timeline_event", Long.class)).isEqualTo(1);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.run_record", Long.class)).isEqualTo(1);
    }

    @AfterEach
    void releaseHttpHooks() {
        handler.beforeLeaseRelease(() -> {
        });
        handler.beforeRead(() -> {
        });
        handler.beforeEmit(() -> {
        });
        authorization.beforeInvocation(() -> {
        });
        await(() -> handler.activeReaders() == 0 && handler.activeWorkers() == 0, 12000);
    }

    @Test
    void scopeAddedAfterInitialAuthorizationDeniesBeforeResponseCommit() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "initial-revision");
        AtomicBoolean added = new AtomicBoolean();
        handler.beforeRead(() -> {
            if (added.compareAndSet(false, true)) {
                produceSecond(run, true);
            }
        });
        var response = get("events", null);
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body())
                .doesNotContain("event: entry", "second HTTP canary", "synthetic HTTP title", "count");
        assertThat(secondVotes()).containsExactly(true, false);
        assertThat(jdbc
                .queryForObject("SELECT scope_revision FROM f07_proof.conversation WHERE uuid=?", Long.class,
                        conversation))
                .isEqualTo(2);
    }

    @Test
    void scopeAddedAfterCommittedCommentSuppressesPreviouslyReadBatchAndMetadata() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "emit-revision");
        timeline
                .append(conversation, run, "first unsent HTTP canary", Set.of(first),
                        Instant.parse("2100-01-01T00:00:00Z"));
        AtomicBoolean added = new AtomicBoolean();
        handler.beforeEmit(() -> {
            if (added.compareAndSet(false, true)) {
                produceSecond(run, true);
            }
        });
        var response = get("events", null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body())
                .contains(": connected\n\n", "event: forbidden\ndata:\n\n")
                .doesNotContain("event: entry", "event: complete", "first unsent HTTP canary", "second HTTP canary",
                        "synthetic HTTP title", "count", "scope-revoked", "unauthenticated");
        assertThat(secondVotes()).containsExactly(true, false);
        await(() -> handler.activeReaders() == 0, 2000);
        assertThat(handler.completedProbe().end).isEqualTo(ConversationStreamHttp.End.UNVERIFIED_ACCESS);
        assertThat(handler.completedProbe().contextClean).isTrue();
    }

    @Test
    void allowedScopeChangeIsReadOnlyAfterActualFreshVotesAndKeepsTerminalTruth() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "allowed-emit-revision");
        timeline
                .append(conversation, run, "first allowed HTTP canary", Set.of(first),
                        Instant.parse("2100-01-01T00:00:00Z"));
        AtomicBoolean added = new AtomicBoolean();
        handler.beforeEmit(() -> {
            if (added.compareAndSet(false, true)) {
                produceSecond(run, false);
                timeline.complete(run);
            }
        });
        var response = get("events", null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body())
                .contains("first allowed HTTP canary", "second HTTP canary", "event: complete\ndata:\n\n")
                .doesNotContain("event: forbidden");
        assertThat(secondVotes()).hasSizeGreaterThanOrEqualTo(2).containsOnly(true);
        assertThat(response.body().indexOf("first allowed HTTP canary"))
                .isLessThan(response.body().indexOf("second HTTP canary"));
    }

    @Test
    void idleHeartbeatThenAuthLossProducesUniformForbiddenWithoutSuccessfulCompletion() throws Exception {
        storedRun(conversation, ACTOR, "idle-auth-loss");
        try (var response = openStream()) {
            assertThat(response.status).isEqualTo(200);
            assertThat(response.frame()).isEqualTo(": connected");
            assertThat(response.frame()).isEqualTo(": keep-alive");
            AUTHORITY.authStatus = 503;
            String terminal = response.until("event: forbidden", 20);
            assertThat(terminal)
                    .contains("event: forbidden\ndata:")
                    .doesNotContain("event: complete", "scope-revoked", "unauthenticated");
            await(() -> handler.activeReaders() == 0, 6000);
            assertThat(handler.completedProbe().end).isEqualTo(ConversationStreamHttp.End.UNVERIFIED_ACCESS);
            assertThat(handler.completedProbe().contextClean).isTrue();
        }
    }

    @Test
    void idleOpaLossUsesTheSameContentFreeForbiddenTerminal() throws Exception {
        storedRun(conversation, ACTOR, "idle-opa-loss");
        try (var response = openStream()) {
            assertThat(response.status).isEqualTo(200);
            assertThat(response.frame()).isEqualTo(": connected");
            assertThat(response.frame()).isEqualTo(": keep-alive");
            AUTHORITY.opaUnavailable = true;
            assertThat(response.until("event: forbidden", 20))
                    .contains("event: forbidden\ndata:")
                    .doesNotContain("event: complete", "scope-revoked", "unauthenticated", "synthetic HTTP title");
            await(() -> handler.activeReaders() == 0, 6000);
            assertThat(handler.completedProbe().end).isEqualTo(ConversationStreamHttp.End.UNVERIFIED_ACCESS);
        }
    }

    @Test
    void httpCommandBoundsRejectWithoutCreatingAnyLedgerRows() throws Exception {
        assertThat(post("runs", "x".repeat(129), new byte[1]).statusCode()).isEqualTo(400);
        assertThat(post("runs", "large-http-command", new byte[4097]).statusCode()).isEqualTo(413);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.command_record", Long.class)).isZero();
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.run_record", Long.class)).isZero();
        var accepted = post("runs", "x".repeat(128), new byte[4096]);
        assertThat(accepted.statusCode()).isEqualTo(202);
        assertThat(jdbc.queryForObject("SELECT count(*) FROM f07_proof.command_record", Long.class)).isEqualTo(1);
    }

    @Test
    void boundedReadersRejectFifthBeforeAsyncWhileOrdinaryAsyncRequestStillWorks() throws Exception {
        storedRun(conversation, ACTOR, "capacity");
        CountDownLatch entered = new CountDownLatch(4);
        CountDownLatch release = new CountDownLatch(1);
        handler.beforeEmit(() -> {
            entered.countDown();
            awaitLatch(release);
        });
        var responses = new ArrayList<Stream>();
        try {
            for (int index = 0; index < 4; index++) {
                var response = openStream();
                responses.add(response);
                assertThat(response.status)
                        .as("stream open %s, workers %s, reservations %s", index, handler.activeWorkers(),
                                handler.activeReaders())
                        .isEqualTo(200);
                assertThat(response.frame()).isEqualTo(": connected");
            }
            assertThat(entered.await(2, TimeUnit.SECONDS)).isTrue();
            assertThat(handler.activeReaders()).isEqualTo(4);
            assertThat(handler.activeWorkers()).isEqualTo(4);
            int rejects = handler.rejectedReaders();
            var denied = get("events", null);
            assertThat(denied.statusCode()).isEqualTo(503);
            assertThat(handler.rejectedReaders()).isEqualTo(rejects + 1);
            var ordinary = http
                    .send(HttpRequest
                            .newBuilder(URI
                                    .create("http://127.0.0.1:" + port
                                            + "/api/v1/conversation-stream-proof/ordinary-servlet-async"))
                            .timeout(Duration.ofSeconds(2))
                            .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                            .GET()
                            .build(), HttpResponse.BodyHandlers.ofString());
            assertThat(ordinary.statusCode()).isEqualTo(200);
            assertThat(JSON.readTree(ordinary.body()).path("status").asText()).isEqualTo("ordinary");
            assertThat(handler.activeWorkers()).isEqualTo(4);
        } finally {
            release.countDown();
            for (var response : responses) {
                response.close();
            }
        }
        await(() -> handler.activeReaders() == 0 && handler.activeWorkers() == 0, 6000);
        assertThat(handler.completedProbe().contextClean).isTrue();
    }

    @Test
    void nonReadingClientNaturallyTimesOutAnActualBlockedWriteAndReleasesCapacityBeforeClientClose() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "nonreader");
        String payload = "N".repeat(30000);
        for (int index = 0; index < 64; index++) {
            timeline.append(conversation, run, payload, Set.of(first), Instant.parse("2100-01-01T00:00:00Z"));
        }
        timeline.complete(run);
        long requestStarted = System.nanoTime();
        try (Connection connection = jdbc.getDataSource().getConnection(); Socket socket = new Socket()) {
            socket.setReceiveBufferSize(1024);
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 2000);
            socket.setReceiveBufferSize(1024);
            int remotePort = socket.getLocalPort();
            var request = "GET /api/v1/conversation-stream-proof/" + conversation + "/events HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + port + "\r\nX-APP-CERTIFICATE: " + ForwardedCertificateFixtures.LEAF_DER
                    + "\r\nConnection: close\r\n\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            AtomicReference<SocketWrapperBase<NioChannel>> accepted = new AtomicReference<>();
            await(() -> {
                var server = (TomcatWebServer) webContext.getWebServer();
                var protocol = (AbstractProtocol<?>) server.getTomcat().getConnector().getProtocolHandler();
                NioEndpoint endpoint = ReflectionTestUtils.invokeMethod(protocol, "getEndpoint");
                accepted
                        .set(endpoint
                                .getConnections()
                                .stream()
                                .filter(wrapper -> wrapper.getRemotePort() == remotePort
                                        && "127.0.0.1".equals(wrapper.getRemoteAddr()))
                                .findFirst()
                                .orElse(null));
                return accepted.get() != null;
            }, 2000);
            var wrapper = accepted.get();
            int actualSend = wrapper.getSocket().getIOChannel().socket().getSendBufferSize();
            int actualReceive = socket.getReceiveBufferSize();
            int actualApplication = wrapper.getSocketBufferHandler().getWriteBuffer().capacity();
            assertThat(wrapper.getWriteTimeout()).isEqualTo(750);
            assertThat(64L * 30000).isGreaterThan((long) actualSend + actualReceive + actualApplication);
            AtomicReference<ConversationStreamHttp.Probe> blocked = new AtomicReference<>();
            java.util.concurrent.atomic.AtomicLong blockedWriteStarted = new java.util.concurrent.atomic.AtomicLong();
            try {
                await(() -> {
                    var probe = handler.activeProbe(remotePort);
                    Thread writer = probe == null ? null : probe.writer;
                    long writeStarted = probe == null ? 0 : probe.writeStarted;
                    if (writer == null || !probe.writeActive
                            || System.nanoTime() - writeStarted < TimeUnit.MILLISECONDS.toNanos(300)) {
                        return false;
                    }
                    boolean inActualWrite = Arrays
                            .stream(writer.getStackTrace())
                            .anyMatch(frame -> frame.getClassName().contains("NioSocketWrapper")
                                    && frame.getMethodName().equals("doWrite"));
                    boolean sameWrite = inActualWrite && probe.writeActive && probe.writeStarted == writeStarted;
                    if (sameWrite) {
                        blocked.set(probe);
                        blockedWriteStarted.set(writeStarted);
                    }
                    return sameWrite;
                }, 6000);
            } catch (org.awaitility.core.ConditionTimeoutException failure) {
                var observed = handler.activeProbe(remotePort);
                if (observed == null) {
                    observed = handler.completedProbe();
                }
                throw new AssertionError("Nonreader diagnostic: matched="
                        + (observed != null && observed.remotePort == remotePort) + ", end="
                        + (observed == null ? "ABSENT" : observed.end) + ", offered="
                        + (observed == null ? 0 : observed.offered.get()) + ", written="
                        + (observed == null ? 0 : observed.written.get()) + ", readTimeout=" + wrapper.getReadTimeout()
                        + ", writeTimeout=" + wrapper.getWriteTimeout() + ", clientReceive="
                        + socket.getReceiveBufferSize() + ", workers=" + handler.activeWorkers());
            }
            var probe = blocked.get();
            assertThat(probe.transactionAtWrite).isFalse();
            assertThat(probe.written.get()).isLessThan(probe.offered.get());
            long blockedAt = System.nanoTime();
            // An independent real transaction must commit while this exact writer is still outstanding.
            {
                connection.setAutoCommit(false);
                try (var statement = connection.createStatement()) {
                    statement.execute("SET LOCAL lock_timeout='50ms'");
                }
                try (var lock = connection
                        .prepareStatement("SELECT uuid FROM f07_proof.conversation WHERE uuid=? FOR UPDATE NOWAIT")) {
                    lock.setObject(1, conversation);
                    try (var rows = lock.executeQuery()) {
                        assertThat(rows.next()).isTrue();
                    }
                }
                try (var update = connection
                        .prepareStatement("UPDATE f07_proof.conversation SET title=? WHERE uuid=?")) {
                    update.setString(1, "concurrent socket proof");
                    update.setObject(2, conversation);
                    assertThat(update.executeUpdate()).isEqualTo(1);
                }
                connection.commit();
            }
            assertThat(probe.writeActive)
                    .as("write remains blocked across independent commit; end %s, offered %s, written %s", probe.end,
                            probe.offered.get(), probe.written.get())
                    .isTrue();
            assertThat(probe.writeStarted)
                    .as("same outstanding write across independent commit")
                    .isEqualTo(blockedWriteStarted.get());
            assertThat(socket.isClosed()).isFalse();
            await(() -> probe.finished != 0, 3000);
            long releasedAt = System.nanoTime();
            assertThat(probe.end).isEqualTo(ConversationStreamHttp.End.WRITE_TIMEOUT);
            assertThat(probe.finished).isGreaterThan(blockedAt);
            assertCleanWorker(probe);
            assertThat(probe.transactionAtWrite).isFalse();
            var server = (TomcatWebServer) webContext.getWebServer();
            var protocol = (AbstractProtocol<?>) server.getTomcat().getConnector().getProtocolHandler();
            NioEndpoint endpoint = ReflectionTestUtils.invokeMethod(protocol, "getEndpoint");
            await(() -> !endpoint.getConnections().contains(wrapper), 2000);
            assertThat(probe.writer).isNull();
            assertThat(handler.activeWorkers()).isZero();
            assertThat(handler.activeReaders()).isZero();
            assertThat(probe.maximumFrame.get()).isLessThanOrEqualTo(32768);
            assertThat(socket.isClosed()).as("client remains open until all release evidence is observed").isFalse();
            assertThat(releasedAt - requestStarted).isLessThan(TimeUnit.SECONDS.toNanos(8));
            var evidence = new java.util.LinkedHashMap<String, Object>(Map
                    .of("actualSendBuffer", actualSend, "actualReceiveBuffer", actualReceive, "actualApplicationBuffer",
                            actualApplication, "writeTimeoutMs", wrapper.getWriteTimeout(), "observedBlockedNioWrite",
                            true, "concurrentCommitWhileBlocked", true, "naturalWriteTimeout", probe.end.name(),
                            "releasedBeforeClientClose", !socket.isClosed(), "elapsedMs",
                            TimeUnit.NANOSECONDS.toMillis(releasedAt - requestStarted), "maximumFrameBytes",
                            probe.maximumFrame.get()));
            evidence.put("minimumObservedWriteAgeMs", 300);
            evidence.put("sameOutstandingWriteAcrossCommit", probe.writeStarted == blockedWriteStarted.get());
            evidence.put("serverConnectionReleasedBeforeClientClose", !endpoint.getConnections().contains(wrapper));
            java.nio.file.Files
                    .writeString(java.nio.file.Path.of("target", "f07-http-write-proof.json"),
                            JSON.writeValueAsString(evidence));
        }
    }

    @Test
    void unauthenticatedSseCannotCommitAConnectedCommentOrEntry() throws Exception {
        var missing = http.send(request("events").GET().build(), HttpResponse.BodyHandlers.ofString());
        var foreign = http
                .send(request("events")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.ISSUER_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        assertThat(missing.statusCode()).isEqualTo(401);
        assertThat(foreign.statusCode()).isEqualTo(401);
        assertThat(missing.body()).doesNotContain(": connected", "event:", "synthetic HTTP title");
        assertThat(foreign.body()).doesNotContain(": connected", "event:", "synthetic HTTP title");
        assertThat(handler.activeReaders()).isZero();
        assertThat(handler.activeWorkers()).isZero();
    }

    @Test
    void realClientAbortReleasesWriterReservationAndContext() throws Exception {
        storedRun(conversation, ACTOR, "abort-stream");
        ConversationStreamHttp.Probe probe;
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 2000);
            socket.setSoTimeout(3000);
            socket
                    .getOutputStream()
                    .write(("GET /api/v1/conversation-stream-proof/" + conversation
                            + "/events HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nX-APP-CERTIFICATE: "
                            + ForwardedCertificateFixtures.LEAF_DER + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            var reader = new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            assertThat(reader.readLine()).startsWith("HTTP/1.1 200");
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                // Discard headers without retaining or logging their values.
            }
            while ((line = reader.readLine()) != null && !line.equals(": connected")) {
                // Skip chunk-size lines until the producer's connected comment has reached the client.
            }
            assertThat(line).isEqualTo(": connected");
            probe = handler.activeProbe(socket.getLocalPort());
            assertThat(probe).isNotNull();
            socket.setSoLinger(true, 0);
        }
        await(() -> probe.finished != 0, 3000);
        assertThat(probe.end).isEqualTo(ConversationStreamHttp.End.PEER_IO);
        assertCleanWorker(probe);
        assertThat(probe.writer).isNull();
        assertThat(handler.activeReaders()).isZero();
        assertThat(handler.activeWorkers()).isZero();
    }

    @Test
    void ordinaryCallableDispatchIsMeasuredSeparatelyFromQualifiedServletAsync() throws Exception {
        assertThat(get("timeline", null).statusCode()).isEqualTo(200);
        assertThat(handler.lastActor()).isEqualTo(ACTOR);
        handler.resetObservations();
        assertThat(handler.lastActor()).as("this request cannot reuse an earlier actor witness").isNull();
        var response = http
                .send(HttpRequest
                        .newBuilder(URI
                                .create("http://127.0.0.1:" + port
                                        + "/api/v1/conversation-stream-proof/ordinary-async"))
                        .timeout(Duration.ofSeconds(3))
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        java.nio.file.Files
                .writeString(java.nio.file.Path.of("target", "f07-ordinary-callable-observation.json"),
                        JSON.writeValueAsString(Map.of("observedStatus", response.statusCode(), "baselineOnly", true)));
        // This is a baseline measurement, not a claim that Callable authorization or streaming passed.
        assertThat(handler.lastActor()).isEqualTo(ACTOR);
        assertThat(handler.activeReaders()).isZero();
        assertThat(handler.activeWorkers()).isZero();
    }

    @Test
    void finishedIsPublishedOnlyAfterActualWorkerAndPermitRelease() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "finished-publication");
        timeline.complete(run);
        CountDownLatch entered = new CountDownLatch(1);
        CountDownLatch release = new CountDownLatch(1);
        AtomicReference<ConversationStreamHttp.Probe> observed = new AtomicReference<>();
        handler.beforeLeaseRelease(() -> {
            observed.set(handler.activeProbe());
            entered.countDown();
            awaitLatch(release);
        });
        var request = http
                .sendAsync(request("events")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofString());
        try {
            assertThat(entered.await(3, TimeUnit.SECONDS)).isTrue();
            assertThat(observed.get()).isNotNull();
            assertThat(handler.activeWorkers()).isEqualTo(1);
            assertThat(handler.activeReaders()).isEqualTo(1);
            assertThat(observed.get().finished).as("completion cannot precede release").isZero();
        } finally {
            release.countDown();
        }
        assertThat(request.get(5, TimeUnit.SECONDS).statusCode()).isEqualTo(200);
        await(() -> observed.get().finished != 0, 2000);
        assertThat(handler.activeWorkers()).isZero();
        assertThat(handler.activeReaders()).isZero();
    }

    @Test
    void contextWitnessDetectsARealWorkerCanaryBeforeCleanup() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "context-observation");
        timeline.complete(run);
        handler.beforeEmit(() -> org.slf4j.MDC.put("f07-proof-context", "synthetic-canary"));
        var response = get("events", null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("event: complete");
        await(() -> handler.activeReaders() == 0, 2000);
        var probe = handler.completedProbe();
        assertThat(probe.contextCleanBeforeFinalClear)
                .as("canary must be observed before forced final clear")
                .isFalse();
        assertThat(probe.authorityContextClean)
                .as("canary must be observed before actual F05 authority entry")
                .isFalse();
        assertThat(probe.authorityChecks.get()).isPositive();
        assertThat(probe.contextClean).as("final cleanup must still remove the canary").isTrue();
    }

    @Test
    void oversizedEntryAddedAfterCommitClosesWithoutPartialFrameOrFalseCompletion() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "late-oversize-frame");
        AtomicBoolean appended = new AtomicBoolean();
        handler.beforeEmit(() -> {
            if (appended.compareAndSet(false, true)) {
                authorization.require(ACTOR, timeline.scope(ACTOR, conversation));
                timeline
                        .append(conversation, run, "\\".repeat(30000), Set.of(first),
                                Instant.parse("2100-01-01T00:00:00Z"));
                timeline.complete(run);
            }
        });
        var response = get("events", null);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains(": connected\n\n").doesNotContain("event: entry", "event: complete");
        assertThat(response.body().getBytes(StandardCharsets.UTF_8)).hasSizeLessThanOrEqualTo(32768);
        await(() -> handler.activeReaders() == 0, 2000);
        var probe = handler.completedProbe();
        assertThat(probe.end).isEqualTo(ConversationStreamHttp.End.FRAME_LIMIT);
        assertCleanWorker(probe);
    }

    @Test
    @Timeout(30)
    void partialReaderReleasesActualWriterAndSocketWithinOperationalBound() throws Exception {
        UUID run = storedRun(conversation, ACTOR, "partial-reader");
        for (int index = 0; index < 64; index++) {
            timeline.append(conversation, run, "P".repeat(30000), Set.of(first), Instant.parse("2100-01-01T00:00:00Z"));
        }
        timeline.complete(run);
        long started = System.nanoTime();
        try (Socket socket = new Socket(); var pool = java.util.concurrent.Executors.newSingleThreadExecutor()) {
            socket.setReceiveBufferSize(1024);
            socket.connect(new java.net.InetSocketAddress("127.0.0.1", port), 2000);
            socket.setReceiveBufferSize(1024);
            socket.setSoTimeout(1000);
            int remotePort = socket.getLocalPort();
            socket
                    .getOutputStream()
                    .write(("GET /api/v1/conversation-stream-proof/" + conversation
                            + "/events HTTP/1.1\r\nHost: 127.0.0.1:" + port + "\r\nX-APP-CERTIFICATE: "
                            + ForwardedCertificateFixtures.LEAF_DER + "\r\nConnection: close\r\n\r\n")
                            .getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            await(() -> handler.activeProbe(remotePort) != null, 2000);
            var probe = handler.activeProbe(remotePort);
            var server = (TomcatWebServer) webContext.getWebServer();
            var protocol = (AbstractProtocol<?>) server.getTomcat().getConnector().getProtocolHandler();
            NioEndpoint endpoint = ReflectionTestUtils.invokeMethod(protocol, "getEndpoint");
            var wrapper = endpoint
                    .getConnections()
                    .stream()
                    .filter(value -> value.getRemotePort() == remotePort && "127.0.0.1".equals(value.getRemoteAddr()))
                    .findFirst()
                    .orElseThrow();
            await(() -> {
                Thread writer = probe.writer;
                return writer != null && probe.writeActive
                        && System.nanoTime() - probe.writeStarted >= TimeUnit.MILLISECONDS.toNanos(300)
                        && Arrays
                                .stream(writer.getStackTrace())
                                .anyMatch(frame -> frame.getClassName().contains("NioSocketWrapper")
                                        && frame.getMethodName().equals("doWrite"));
            }, 6000);
            long writtenBeforeRead = probe.written.get();
            var input = socket.getInputStream();
            java.util.concurrent.atomic.AtomicLong received = new java.util.concurrent.atomic.AtomicLong(
                    input.readNBytes(262144).length);
            assertThat(received.get()).isEqualTo(262144);
            socket.setSoTimeout(250);
            AtomicBoolean stop = new AtomicBoolean();
            var reader = pool.submit(() -> {
                byte[] buffer = new byte[1024];
                while (!stop.get() && probe.finished == 0) {
                    try {
                        int count = input.read(buffer);
                        if (count < 0) {
                            return;
                        }
                        received.addAndGet(count);
                    } catch (java.net.SocketTimeoutException timeout) {
                        // Poll actual worker completion while the still-open client supplies no additional bytes.
                    } catch (java.io.IOException disconnected) {
                        return;
                    }
                    java.util.concurrent.locks.LockSupport.parkNanos(TimeUnit.MILLISECONDS.toNanos(100));
                    if (Thread.currentThread().isInterrupted()) {
                        return;
                    }
                }
            });
            try {
                try {
                    await(() -> probe.written.get() > writtenBeforeRead, 2000);
                } catch (org.awaitility.core.ConditionTimeoutException failure) {
                    throw new AssertionError("Partial-reader diagnostic: end=" + probe.end + ", before="
                            + writtenBeforeRead + ", after=" + probe.written.get() + ", offered=" + probe.offered.get()
                            + ", received=" + received.get() + ", actualReceive=" + socket.getReceiveBufferSize());
                }
                await(() -> probe.finished != 0, 22000);
                assertCleanWorker(probe);
                assertThat(probe.writer).isNull();
                assertThat(handler.activeReaders()).isZero();
                assertThat(handler.activeWorkers()).isZero();
                await(() -> !endpoint.getConnections().contains(wrapper), 2000);
                assertThat(socket.isClosed()).isFalse();
                long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
                assertThat(elapsed).isLessThan(22000);
                java.nio.file.Files
                        .writeString(java.nio.file.Path.of("target", "f07-http-partial-reader-proof.json"), JSON
                                .writeValueAsString(Map
                                        .of("pattern", "initial262144bytes_then1024bytes_per100ms",
                                                "actualServerProgressAfterRead",
                                                probe.written.get() > writtenBeforeRead, "clientBytesRead",
                                                received.get(), "end", probe.end.name(), "elapsedMs", elapsed,
                                                "workerReleased", probe.finished != 0, "serverConnectionReleased",
                                                !endpoint.getConnections().contains(wrapper), "clientStillOpen",
                                                !socket.isClosed())));
            } finally {
                stop.set(true);
            }
            reader.get(2, TimeUnit.SECONDS);
        }
    }

    private static void assertCleanWorker(ConversationStreamHttp.Probe probe) {
        assertThat(probe.contextCleanBeforeFinalClear).isTrue();
        assertThat(probe.authorityContextClean).isTrue();
        assertThat(probe.authorityThreadMatches).isTrue();
        assertThat(probe.authorityChecks.get()).isPositive();
        assertThat(probe.contextClean).isTrue();
    }

    private void produceSecond(UUID run, boolean revoke) {
        assertThat(TransactionSynchronizationManager.isActualTransactionActive()).isFalse();
        authorization.require(ACTOR, new ConversationTimeline.Scope(conversation, ACTOR, profile, 1, Set.of(second)));
        timeline.append(conversation, run, "second HTTP canary", Set.of(second), Instant.parse("2100-01-01T00:00:00Z"));
        if (revoke) {
            try {
                allow(Set.of(first));
            } catch (Exception failure) {
                throw new AssertionError("Synthetic fixture failed", failure);
            }
        }
    }

    private List<Boolean> secondVotes() {
        return AUTHORITY.exchanges
                .stream()
                .filter(exchange -> exchange.path().equals("/v1/data/method")
                        && exchange.request().at("/input/requestedResource/name").asText().equals("certificates")
                        && exchange.request().at("/input/requestedResource/uuids/0").asText().equals(second.toString()))
                .map(exchange -> exchange.response().at("/result/authorized").asBoolean())
                .toList();
    }

    private Stream openStream() throws Exception {
        var response = http
                .send(request("events")
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .GET()
                        .build(), HttpResponse.BodyHandlers.ofInputStream());
        return new Stream(response.statusCode(), response.body());
    }

    private static final class Stream implements AutoCloseable {
        private final int status;
        private final InputStream input;
        private final BufferedReader reader;

        Stream(int status, InputStream input) {
            this.status = status;
            this.input = input;
            reader = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        }

        String frame() throws Exception {
            var value = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null && !line.isEmpty()) {
                if (!value.isEmpty()) {
                    value.append('\n');
                }
                value.append(line);
            }
            return value.toString();
        }

        String until(String expected, int frames) throws Exception {
            var result = new StringBuilder();
            for (int index = 0; index < frames; index++) {
                String frame = frame();
                result.append(frame).append("\n\n");
                if (frame.contains(expected) || frame.isEmpty()) {
                    return result.toString();
                }
            }
            return result.toString();
        }

        @Override
        public void close() throws Exception {
            input.close();
        }
    }

    private static void await(BooleanSupplier condition, long milliseconds) {
        org.awaitility.Awaitility
                .await()
                .pollDelay(Duration.ZERO)
                .pollInterval(Duration.ofMillis(5))
                .atMost(Duration.ofMillis(milliseconds))
                .until(condition::getAsBoolean);
    }

    private static void awaitLatch(CountDownLatch latch) {
        try {
            if (!latch.await(6, TimeUnit.SECONDS)) {
                throw new AssertionError("HTTP proof barrier timed out");
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new AssertionError("HTTP proof interrupted");
        }
    }

    private HttpResponse<String> post(String suffix, String key, byte[] body) throws Exception {
        return http
                .send(request(suffix)
                        .header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER)
                        .header("Idempotency-Key", key)
                        .header("Content-Type", "application/octet-stream")
                        .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                        .build(), HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> get(String suffix, String cursor) throws Exception {
        var request = request(suffix).header("X-APP-CERTIFICATE", ForwardedCertificateFixtures.LEAF_DER);
        if (cursor != null) {
            request.header("Last-Event-ID", cursor);
        }
        return http.send(request.GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private UUID storedRun(UUID target, UUID owner, String key) {
        return timeline
                .command(timeline.scope(owner, target), ConversationTimeline.CommandKind.START, key,
                        "trusted synthetic producer".getBytes(StandardCharsets.UTF_8))
                .orElseThrow()
                .runId();
    }

    private UUID foreignConversation() {
        UUID foreign = UUID.randomUUID();
        jdbc
                .update("INSERT INTO f07_proof.conversation VALUES (?,?,?,1,0,?,NULL)", foreign,
                        UUID.fromString("00000000-0000-4000-8000-000000000072"), profile, "foreign HTTP title");
        jdbc.update("INSERT INTO f07_proof.retained_certificate VALUES (?,?)", foreign, first);
        return foreign;
    }

    private HttpRequest.Builder request(String suffix) {
        return request(conversation, suffix);
    }

    private HttpRequest.Builder request(UUID target, String suffix) {
        return HttpRequest
                .newBuilder(URI
                        .create("http://127.0.0.1:" + port + "/api/v1/conversation-stream-proof/" + target + "/"
                                + suffix))
                .timeout(Duration.ofSeconds(8));
    }

    private UUID certificate() {
        X509CertificateEntity c = new X509CertificateEntity();
        c.setCommonName("synthetic-f07-http");
        c.setSubjectDn("CN=synthetic-f07-http");
        c.setIssuerDn("CN=synthetic issuer");
        c.setSerialNumber(UUID.randomUUID().toString());
        c.setState(CertificateState.ISSUED);
        c.setValidationStatus(CertificateValidationStatus.VALID);
        c.setRaProfileUuid(profile);
        return certificates.saveAndFlush(c).getUuid();
    }

    private void allow(Set<UUID> allowed) throws Exception {
        AUTHORITY.principal = JSON
                .writeValueAsString(Map
                        .of("user", Map.of("uuid", ACTOR.toString(), "username", "synthetic-f07-http", "enabled", true),
                                "roles", List.of(), "permissions",
                                Map
                                        .of("allowAllResources", false, "resources", List
                                                .of(Map
                                                        .of("name", "certificates", "allowAllActions", false, "actions",
                                                                List.of(), "objects",
                                                                allowed
                                                                        .stream()
                                                                        .map(id -> Map
                                                                                .of("uuid", id.toString(), "allow",
                                                                                        List.of("detail"), "deny",
                                                                                        List.of()))
                                                                        .toList()),
                                                        Map
                                                                .of("name", "raProfiles", "allowAllActions", false,
                                                                        "actions", List.of(), "objects",
                                                                        List
                                                                                .of(Map
                                                                                        .of("uuid", profile.toString(),
                                                                                                "allow",
                                                                                                List.of("members"),
                                                                                                "deny", List.of()))),
                                                        Map
                                                                .of("name", "groups", "allowAllActions", false,
                                                                        "actions", List.of(), "objects", List.of())))));
    }
}
