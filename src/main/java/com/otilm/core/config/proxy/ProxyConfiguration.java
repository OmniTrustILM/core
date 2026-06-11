package com.otilm.core.config.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import jakarta.annotation.PostConstruct;
import java.net.Authenticator;

/**
 * Inspired by <a href="https://github.com/Orange-OpenSource/spring-boot-autoconfigure-proxy">spring-boot-autoconfigure-proxy</a>
 */
@Configuration
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
public class ProxyConfiguration {
    private static final Logger logger = LoggerFactory.getLogger(ProxyConfiguration.class);

    private static final String[] PROTOCOLS = {"http", "https", "ftp"};

    @PostConstruct
    public void setupProxyConfiguration() {
        MultiServerAuthenticator msa = new MultiServerAuthenticator();

        for (String protocol : PROTOCOLS) {
            ProxySettings proxySettings = ProxySettings.read(protocol);
            if (proxySettings != null) {
                // CASE 2: auto-conf from ENV
                logger.info("Configuring proxy for {} from env '{}': {}", protocol, proxySettings.getEnvName(), proxySettings);

                // set password authentication if specified
                if (proxySettings.getUsername() != null && proxySettings.getPassword() != null) {
                    msa.add(proxySettings.getHost() + ":" + proxySettings.getPort(), proxySettings.getUsername(), proxySettings.getPassword());
                }

                // set proxy properties
                System.setProperty(protocol + ".proxyHost", proxySettings.getHost());
                System.setProperty(protocol + ".proxyPort", String.valueOf(proxySettings.getPort()));
                if (proxySettings.getNoProxyHosts() != null && proxySettings.getNoProxyHosts().length > 0) {
                    System.setProperty(protocol + ".nonProxyHosts", String.join("|", proxySettings.getNoProxyHosts()));
                }
            }
        }

        // install default authenticator (if not empty)
        if (msa.size() > 0) {
            // see: https://www.oracle.com/technetwork/java/javase/8u111-relnotes-3124969.html
            System.setProperty("jdk.http.auth.tunneling.disabledSchemes", "");
            Authenticator.setDefault(msa);
        }
    }

}
