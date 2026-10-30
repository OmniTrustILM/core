package com.otilm.core.auth.oauth2;

import com.otilm.api.model.core.settings.authentication.AuthenticationSettingsDto;
import com.otilm.core.settings.AuthenticationSettingsSnapshot;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthenticationSnapshotRequestFilterTest {

    private final AuthenticationSnapshotRequestFilter filter = new AuthenticationSnapshotRequestFilter();

    @BeforeEach
    @AfterEach
    void clearHolder() {
        AuthenticationSnapshotRequestHolder.clear();
    }

    @Test
    void snapshotPublishedByOneRequest_isNotVisibleToTheNextOneOnTheSameThread() throws Exception {
        // given - the first request publishes a snapshot, as the JWT decoder does
        List<AuthenticationSettingsSnapshot> observedOnEntry = new ArrayList<>();
        FilterChain publishing = (request, response) -> {
            observedOnEntry.add(AuthenticationSnapshotRequestHolder.get());
            AuthenticationSnapshotRequestHolder.set(snapshot(1L));
        };

        // when - two requests are served in sequence on the same thread
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), publishing);
        assertThat(AuthenticationSnapshotRequestHolder.get()).isNull();
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), publishing);

        // then - neither request started with the other's snapshot, and nothing is left behind
        assertThat(observedOnEntry).hasSize(2).containsOnlyNulls();
        assertThat(AuthenticationSnapshotRequestHolder.get()).isNull();
    }

    @Test
    void snapshotIsClearedEvenWhenTheChainFails() {
        // given - a request that publishes a snapshot and then fails
        FilterChain failing = (request, response) -> {
            AuthenticationSnapshotRequestHolder.set(snapshot(2L));
            throw new ServletException("downstream failure");
        };

        // when / then - the failure propagates but the thread is left clean
        assertThatThrownBy(() -> filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), failing))
                .isInstanceOf(ServletException.class);
        assertThat(AuthenticationSnapshotRequestHolder.get()).isNull();
    }

    @Test
    void snapshotPublishedOutsideAnyRequest_isNotVisibleInsideTheChain() throws IOException, ServletException {
        // given - a snapshot left on the thread by something that did not go through this filter
        AuthenticationSnapshotRequestHolder.set(snapshot(3L));
        List<AuthenticationSettingsSnapshot> observedOnEntry = new ArrayList<>();
        FilterChain observing = (request, response) -> observedOnEntry.add(AuthenticationSnapshotRequestHolder.get());

        // when
        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), observing);

        // then
        assertThat(observedOnEntry).hasSize(1).containsOnlyNulls();
    }

    private static AuthenticationSettingsSnapshot snapshot(long generation) {
        return new AuthenticationSettingsSnapshot(new AuthenticationSettingsDto(), generation);
    }
}
