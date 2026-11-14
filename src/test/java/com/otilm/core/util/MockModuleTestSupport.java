package com.otilm.core.util;

import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.TestExecutionListeners.MergeMode;

/** Resets shared module mocks without replacing a test's real authentication or authorization clients. */
@TestExecutionListeners(value = MockBeanResetListener.class, mergeMode = MergeMode.MERGE_WITH_DEFAULTS)
public abstract class MockModuleTestSupport {
}
