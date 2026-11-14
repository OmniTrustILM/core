package com.otilm.core.security.ai;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.tomcat.TomcatWebServer;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizerBeanPostProcessor;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.boot.web.server.servlet.context.AnnotationConfigServletWebServerApplicationContext;
import org.springframework.boot.web.server.servlet.context.ServletWebServerInitializedEvent;
import org.springframework.boot.web.servlet.ServletContextInitializer;
import org.springframework.context.SmartLifecycle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Real Boot lifecycle/TLS with synthetic certificates, without workload or business-authority acceptance. */
class AiRuntimeNativeBootTest {
    private final RuntimeProxyTomcatBindingTest material = new RuntimeProxyTomcatBindingTest();
    private final AtomicReference<TomcatWebServer> server = new AtomicReference<>();
    private AnnotationConfigServletWebServerApplicationContext context;
    private RuntimeProxyTransport transport;
    @TempDir
    Path directory;

    @BeforeEach
    void prepare() throws Exception {
        material.directory = directory;
        material.certificates();
        transport = material.transport(-1);
    }

    @AfterEach
    void cleanup() throws Exception {
        if (context != null) {
            context.close();
        }
        transport.disable();
        if (server.get() != null) {
            server.get().getTomcat().destroy();
        }
    }

    @Test
    void actualBootStartsNativeAfterOrdinaryAndClosesBeforeStopOrRestart() throws Exception {
        context = application(true);
        context.refresh();
        int port = transport.connector().getLocalPort();
        assertThat(port).isPositive();
        assertThat(ordinary()).isEqualTo("ordinary");
        assertThat(material.nativePost(port).body()).isEqualTo(RuntimePeerRole.RUNNER_PROXY.name());
        context.stop();
        assertBindable(port);
        context.start();
        assertThat(ordinary()).isEqualTo("ordinary");
        assertThat(transport.disabled()).isTrue();
        assertBindable(port);
        assertThat(server.get().getTomcat().getService().findConnectors()).hasSize(1);
    }

    @Test
    void absentTrustedTransportKeepsOrdinaryBootAndAddsNoNativeConnector() throws Exception {
        context = application(false);
        context.refresh();
        assertThat(ordinary()).isEqualTo("ordinary");
        assertThat(server.get().getTomcat().getService().findConnectors()).hasSize(1);
        assertThat(transport.connector().getLocalPort()).isNegative();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void failedRefreshAfterNativeAttachmentStillDestroysNativeConnectors(boolean beforeNativeLifecycleStart)
            throws Exception {
        context = application(true);
        var attachedPort = new AtomicInteger(-1);
        context.registerBean("lateFailure", SmartLifecycle.class, () -> new SmartLifecycle() {
            @Override
            public void start() {
                attachedPort.set(transport.connector().getLocalPort());
                throw new IllegalStateException("synthetic-late-lifecycle-failure");
            }

            @Override
            public void stop() {
                // Startup fails before this synthetic lifecycle acquires any resources.
            }

            @Override
            public boolean isRunning() {
                return false;
            }

            @Override
            public int getPhase() {
                return beforeNativeLifecycleStart
                        ? WebServerApplicationContext.START_STOP_LIFECYCLE_PHASE + 1
                        : WebServerApplicationContext.GRACEFUL_SHUTDOWN_PHASE + 2;
            }
        });
        assertThatThrownBy(context::refresh).isInstanceOf(RuntimeException.class);
        assertThat(attachedPort.get()).isPositive();
        assertThat(transport.disabled()).isTrue();
        assertBindable(attachedPort.get());
    }

    private AnnotationConfigServletWebServerApplicationContext application(boolean trustedTransport) throws Exception {
        var result = new AnnotationConfigServletWebServerApplicationContext();
        result.registerBean("nativeCustomizerProcessor", WebServerFactoryCustomizerBeanPostProcessor.class);
        var factory = material.factory();
        result.registerBean(TomcatServletWebServerFactory.class, () -> factory);
        if (trustedTransport) {
            result.registerBean(RuntimeProxyTransport.class, () -> transport);
        }
        result.register(AiRuntimeNativeConfiguration.class);
        result.registerBean(ServletContextInitializer.class, () -> servletContext -> {
            var registration = servletContext.addServlet("probe", new ProbeServlet());
            registration.setAsyncSupported(false);
            registration.addMapping("/*");
        });
        result.addApplicationListener(event -> {
            if (event instanceof ServletWebServerInitializedEvent initialized
                    && initialized.getApplicationContext() == result) {
                server.set((TomcatWebServer) initialized.getWebServer());
            }
        });
        return result;
    }

    private String ordinary() throws Exception {
        try (var client = HttpClient.newHttpClient()) {
            return client
                    .send(HttpRequest
                            .newBuilder(URI.create("http://127.0.0.1:" + server.get().getPort() + "/api/ordinary"))
                            .timeout(Duration.ofSeconds(2))
                            .GET()
                            .build(), HttpResponse.BodyHandlers.ofString())
                    .body();
        }
    }

    private static void assertBindable(int port) throws IOException {
        try (var socket = new ServerSocket()) {
            socket.setReuseAddress(true);
            socket.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        }
    }

    private static final class ProbeServlet extends HttpServlet {
        private static final long serialVersionUID = 1L;

        @Override
        protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.getWriter().write("ordinary");
        }

        @Override
        protected void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException {
            response.getWriter().write(RuntimeProxyTransport.currentWorkloadPeer().orElseThrow().role().name());
        }
    }
}
