package com.otilm.core.feasibility;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.UUID;
import org.apache.coyote.AbstractProtocol;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.tomcat.servlet.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

@TestConfiguration(proxyBeanMethods = false)
@Import(ConversationStreamProofConfiguration.class)
public class ConversationStreamHttpProofConfiguration {
    @Bean
    ConversationStreamHttp conversationStreamHttp(ConversationTimeline timeline, ConversationStreamFixture fixture,
            ConversationStreamAuthorization authorization, ObjectMapper mapper) {
        return new ConversationStreamHttp(timeline, fixture, authorization, mapper);
    }

    @Bean
    SmartInitializingSingleton registerConversationHttp(
            @Qualifier("requestMappingHandlerMapping") RequestMappingHandlerMapping mapping,
            ConversationStreamHttp handler) {
        return () -> {
            try {
                var options = new RequestMappingInfo.BuilderConfiguration();
                options.setPatternParser(mapping.getPatternParser());
                String base = "/v1/conversation-stream-proof/{conversation}";
                register(mapping, options, handler, base + "/timeline", RequestMethod.GET, "timeline", UUID.class,
                        HttpServletRequest.class);
                register(mapping, options, handler, base + "/events", RequestMethod.GET, "events", UUID.class,
                        HttpServletRequest.class, HttpServletResponse.class);
                register(mapping, options, handler, base + "/runs", RequestMethod.POST, "start", UUID.class,
                        HttpServletRequest.class);
                register(mapping, options, handler, base + "/follow-ups", RequestMethod.POST, "follow", UUID.class,
                        HttpServletRequest.class);
                register(mapping, options, handler, base + "/runs/{run}/cancel", RequestMethod.POST, "cancel",
                        UUID.class, UUID.class, HttpServletRequest.class);
                register(mapping, options, handler, "/v1/conversation-stream-proof/ordinary-async", RequestMethod.GET,
                        "ordinary");
                register(mapping, options, handler, "/v1/conversation-stream-proof/ordinary-servlet-async",
                        RequestMethod.GET, "ordinaryServlet", HttpServletRequest.class, HttpServletResponse.class);
            } catch (NoSuchMethodException failure) {
                throw new IllegalStateException("HTTP proof mapping unavailable");
            }
        };
    }

    private static void register(RequestMappingHandlerMapping mapping, RequestMappingInfo.BuilderConfiguration options,
            ConversationStreamHttp handler, String path, RequestMethod method, String name, Class<?>... parameters)
            throws NoSuchMethodException {
        mapping
                .registerMapping(RequestMappingInfo.paths(path).methods(method).options(options).build(), handler,
                        ConversationStreamHttp.class.getMethod(name, parameters));
    }

    @Bean
    WebServerFactoryCustomizer<TomcatServletWebServerFactory> conversationSocketBounds() {
        return factory -> factory.addConnectorCustomizers(connector -> {
            if (!(connector.getProtocolHandler() instanceof AbstractProtocol<?> protocol)) {
                throw new IllegalStateException("HTTP proof requires ordinary Tomcat protocol");
            }
            protocol.setConnectionTimeout(750);
            if (!connector.setProperty("socket.txBufSize", "1024")
                    || !connector.setProperty("socket.appWriteBufSize", "1024")) {
                throw new IllegalStateException("HTTP proof socket bounds unavailable");
            }
        });
    }
}
