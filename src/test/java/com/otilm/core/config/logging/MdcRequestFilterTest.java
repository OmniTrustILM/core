package com.otilm.core.config.logging;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.ResourceRecord;
import com.otilm.core.api.ExceptionHandlingAdvice;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.util.ApplicationMessageConverters;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * An audit record takes its actor, and completes the objects its operation names, from the MDC of the thread serving
 * the request. Nothing a request put there, in the authentication filters or in its handler, may reach the next request
 * that thread serves, however the request ended.
 */
class MdcRequestFilterTest {

    private static final String FAILED_REQUEST = "/probe/failure-after-affiliation";
    private static final String REFUSED_REQUEST = "/probe/refusal-before-affiliation";
    private static final String UNAUTHENTICATED_REQUEST = "/probe/unauthenticated";
    private static final String RA_PROFILE_UUID = "0f0e5d53-7c2b-4a8e-9f5e-2b1f6d4c3a19";

    private final ProbeController probe = new ProbeController();

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
                .standaloneSetup(probe)
                .setMessageConverters(ApplicationMessageConverters.get())
                .setControllerAdvice(new ExceptionHandlingAdvice())
                .addInterceptors(new RequestResponseInterceptor())
                .addFilters(new MdcRequestFilter())
                .addFilter(MdcRequestFilterTest::refuseAfterNamingTheAuthenticationMethod, UNAUTHENTICATED_REQUEST)
                .addFilter(MdcRequestFilterTest::authenticateBySession, REFUSED_REQUEST)
                .build();
    }

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void affiliatedObjectNamedByAFailedRequest_isNotInheritedByTheNextOne() throws Exception {
        // given - a request that names its affiliated object and then fails in its handler
        mockMvc.perform(post(FAILED_REQUEST)).andExpect(status().isUnprocessableEntity());

        // when - the next request on the thread is refused before it names its own
        mockMvc.perform(post(REFUSED_REQUEST)).andExpect(status().isNotFound());

        // then
        assertThat(probe.affiliatedObjectAtRefusal).isNull();
    }

    @Test
    void authenticationMethodNamedByARequestRefusedBeforeItsHandler_isNotInheritedByTheNextOne() throws Exception {
        // given - a request that its authentication refuses after naming the TOKEN method
        mockMvc.perform(post(UNAUTHENTICATED_REQUEST)).andExpect(status().isUnauthorized());

        // when - the next request on the thread is authenticated by its session
        mockMvc.perform(post(REFUSED_REQUEST)).andExpect(status().isNotFound());

        // then
        assertThat(probe.actorAtRefusal).isEqualTo(new ActorRecord(ActorType.USER, AuthMethod.SESSION, null, null));
    }

    @Test
    void failedRequest_leavesNothingInTheMdcOfItsThread() throws Exception {
        // when
        mockMvc.perform(post(FAILED_REQUEST)).andExpect(status().isUnprocessableEntity());

        // then
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void mdcIsClearedEvenWhenTheChainFails() {
        // given - a chain that names an actor and an affiliated object, then fails outside any handler
        FilterChain failing = (request, response) -> {
            LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
            LoggingHelper.putLogResourceInfo(Resource.RA_PROFILE, true, RA_PROFILE_UUID, "earlier-ra-profile");
            throw new ServletException("downstream failure");
        };
        MdcRequestFilter filter = new MdcRequestFilter();
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        // when / then - the failure propagates and the thread is left clean
        assertThatThrownBy(() -> filter.doFilter(request, response, failing)).isInstanceOf(ServletException.class);
        assertThat(MDC.getCopyOfContextMap()).isNullOrEmpty();
    }

    @Test
    void entriesLeftOnTheThreadOutsideAnyRequest_areNotVisibleToItsHandler() throws Exception {
        // given
        LoggingHelper.putLogResourceInfo(Resource.RA_PROFILE, true, RA_PROFILE_UUID, "left-on-the-thread");

        // when
        mockMvc.perform(post(REFUSED_REQUEST)).andExpect(status().isNotFound());

        // then
        assertThat(probe.affiliatedObjectAtRefusal).isNull();
    }

    /** Refuses a request once it has named the authentication method, as the bearer-token decoder names it first. */
    private static void refuseAfterNamingTheAuthenticationMethod(ServletRequest request, ServletResponse response,
            FilterChain chain) {
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
        ((HttpServletResponse) response).setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }

    /** Names the SESSION method of a request the way the session login filter does, then lets it through. */
    private static void authenticateBySession(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.SESSION);
        chain.doFilter(request, response);
    }

    @RestController
    static final class ProbeController {

        private ResourceRecord affiliatedObjectAtRefusal;
        private ActorRecord actorAtRefusal;

        @PostMapping(FAILED_REQUEST)
        void failAfterNamingItsAffiliatedObject() {
            LoggingHelper.putLogResourceInfo(Resource.RA_PROFILE, true, RA_PROFILE_UUID, "earlier-ra-profile");
            throw new ValidationException("refused after naming its RA profile");
        }

        @PostMapping(REFUSED_REQUEST)
        void refuseBeforeNamingItsAffiliatedObject() throws NotFoundException {
            affiliatedObjectAtRefusal = LoggingHelper.getLogResourceInfo(true);
            actorAtRefusal = LoggingHelper.getActorInfo();
            throw new NotFoundException(Resource.RA_PROFILE.getLabel(), "unknown-ra-profile");
        }
    }
}
