package com.otilm.core.service.handler.discovery;

import com.otilm.core.dao.entity.Discovery;

/**
 * Whether a tick still speaks for its run, decided under the run's row lock. A tick that was overtaken may not end the
 * run or apply what its connector answered.
 */
@FunctionalInterface
public interface DiscoveryTickFence {

    boolean admits(Discovery lockedRun);
}
