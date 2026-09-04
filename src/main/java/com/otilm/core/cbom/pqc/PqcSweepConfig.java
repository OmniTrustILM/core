package com.otilm.core.cbom.pqc;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/** Binds the re-evaluation sweep's deploy-time tuning. */
@Configuration
@EnableConfigurationProperties(PqcSweepProperties.class)
public class PqcSweepConfig {
}
