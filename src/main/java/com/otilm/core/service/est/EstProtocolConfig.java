package com.otilm.core.service.est;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Binds the deploy-time settings of the EST protocol. */
@Configuration
@EnableConfigurationProperties(EstProtocolProperties.class)
public class EstProtocolConfig {
}
