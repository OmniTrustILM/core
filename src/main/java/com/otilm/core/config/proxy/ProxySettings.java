package com.otilm.core.config.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;

/**
 * Inspired by <a href="https://github.com/Orange-OpenSource/spring-boot-autoconfigure-proxy">spring-boot-autoconfigure-proxy</a>
 */
public class ProxySettings {

    private static final Logger logger = LoggerFactory.getLogger(ProxySettings.class);

    private final String forProtocol;
    private final String protocol;
    private final String host;
    private final int port;
    private final String[] noProxyHosts;
    private final String username;
    private final String password;

    public ProxySettings(String forProtocol, String protocol, String host, int port, String[] noProxyHosts, String username, String password) {
        this.forProtocol = forProtocol;
        this.protocol = protocol;
        this.username = username;
        this.password = password;
        this.host = host;
        this.noProxyHosts = noProxyHosts;
        this.port = port;
    }

    /**
     * Returns the proxy protocol (one of {@code http}, {@code socks} or {@code socks5})
     */
    public String getProtocol() {
        return protocol;
    }

    /**
     * Returns the protocol (scheme) this proxy setting applies to
     */
    public String getForProtocol() {
        return forProtocol;
    }

    /**
     * Returns the proxy server host
     */
    public String getHost() {
        return host;
    }

    /**
     * Returns the proxy server port
     */
    public int getPort() {
        return port;
    }

    /**
     * Returns the list of no-proxy server hosts (matchers)
     */
    public String[] getNoProxyHosts() {
        return noProxyHosts;
    }

    /**
     * Returns the proxy username (if requires authentication)
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the proxy password (if requires authentication)
     */
    public String getPassword() {
        return password;
    }

    /**
     * Returns the proxy setting environment variable name
     */
    public String getEnvName() {
        return forProtocol + "_proxy";
    }

    /**
     * Returns the proxy setting environment variable value (hides the password)
     */
    public String getEnvVal() {
        return protocol + "://" + (username == null ? "" : username + ":***@") + host + ":" + port;
    }

    @Override
    public String toString() {
        return "ProxySettingsFromEnv{" +
                "protocol='" + protocol + '\'' +
                ", host='" + host + '\'' +
                ", port=" + port +
                ", forProtocol=" + forProtocol +
                ", noProxyHosts=" + Arrays.toString(noProxyHosts) +
                ", username='" + (username == null ? "(none)" : username) + '\'' +
                ", password='" + (password == null ? "(none)" : "***") + '\'' +
                '}';
    }

    /**
     * Reads and parses the proxy settings from system environment
     *
     * @param protocol determines for which forProtocol the proxy settings shall be read
     * @return parsed setting, or {@code null} if not set
     */
    public static ProxySettings read(String protocol) {
        return parse(protocol, getEnvIgnoreCase(protocol + "_proxy"), getEnvIgnoreCase("no_proxy"));
    }

    static ProxySettings parse(String protocol, String proxyUrl, String noProxy) {
        if (proxyUrl == null) {
            return null;
        }
        try {
            URI url = new URI(proxyUrl);
            if (url.getHost() == null) {
                logger.error("Invalid proxy configuration URL for {}: {} - host not specified", protocol, proxyUrl);
                return null;
            }
            if (url.getPort() == -1) {
                logger.error("Invalid proxy configuration URL for {}: {} - port not specified", protocol, proxyUrl);
                return null;
            }
            // scheme is optional (defaults to http)
            String scheme = url.getScheme() == null ? "http" : url.getScheme();

            // read login/password
            String username = null;
            String password = null;
            String userInfo = url.getUserInfo();
            if (userInfo != null) {
                int idx = userInfo.indexOf(':');
                username = userInfo.substring(0, idx);
                password = userInfo.substring(idx + 1);
            }
            // add no proxy hosts
            String[] noProxyHosts = null;
            if (noProxy != null) {
                noProxyHosts = noProxy.split("\\s*,\\s*");
            }
            return new ProxySettings(protocol, scheme, url.getHost(), url.getPort(), noProxyHosts, username, password);
        } catch (URISyntaxException e) {
            logger.error("Could not decode proxy configuration for {}: {}", protocol, proxyUrl, e);
            return null;
        }
    }


    static String getEnvIgnoreCase(String name) {
        String val = System.getenv(name.toLowerCase());
        return val != null ? val : System.getenv(name.toUpperCase());
    }

}
