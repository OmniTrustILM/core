package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;

/**
 * Whether a tick may still end its run, decided under the run's row lock. A tick that a stop, a resume or another tick
 * has overtaken ends nothing.
 */
@FunctionalInterface
public interface DiscoveryTickFence {

    boolean admits(Discovery lockedRun);
}
