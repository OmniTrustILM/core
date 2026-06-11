package com.otilm.core.config.proxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.util.HashMap;
import java.util.Map;

/**
 * This is an {@link Authenticator} implementation able to manage several servers
 * Inspired by <a href="https://github.com/Orange-OpenSource/spring-boot-autoconfigure-proxy">spring-boot-autoconfigure-proxy</a>
 */
public class MultiServerAuthenticator extends Authenticator {
    private static final Logger logger = LoggerFactory.getLogger(MultiServerAuthenticator.class);

    private final Map<String, PasswordAuthentication> host2Authent = new HashMap<>();

    public void add(String host, String user, String password) {
        host2Authent.put(host, new PasswordAuthentication(user, password.toCharArray()));
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
        String host = "" + getRequestingHost() + ":" + getRequestingPort();
        PasswordAuthentication passwordAuthentication = host2Authent.get(host);
        logger.trace("using proxy authentication for <{}>: {}", host, passwordAuthentication == null ? "none" : passwordAuthentication.getUserName() + "/***");
        return passwordAuthentication;
    }

    public int size() {
        return host2Authent.size();
    }
}
