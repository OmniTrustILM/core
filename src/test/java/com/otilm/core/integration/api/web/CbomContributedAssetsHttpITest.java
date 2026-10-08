package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.cbom.ingest.CbomAssetIngestService;
import com.otilm.core.cbom.ingest.CbomIngestTestFixtures;
import com.otilm.core.cbom.sync.CbomSyncPolicy;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.hibernate.engine.spi.SharedSessionContractImplementor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.orm.jpa.EntityManagerHolder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * The CBOM-scoped asset listing over HTTP: both gates refuse with the platform's 403, an unknown CBOM is a 404, neither
 * gate is asked while the request holds a connection, and the permitted response carries the refs without any of the
 * fenced vocabulary.
 */
@AutoConfigureMockMvc
class CbomContributedAssetsHttpITest extends BaseSpringBootTest {

    private static final Pattern IDENTITY_KEY = Pattern
            .compile("identity[_\\-\\s]?key|absorbed[_\\-\\s]?key|canonical[_\\-\\s]?key", Pattern.CASE_INSENSITIVE);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CbomAssetIngestService ingestService;

    private UUID cbomUuid;

    @BeforeEach
    void seedOneContribution() {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:http");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        cbomUuid = cbomRepository.save(cbom).getUuid();
        assertThat(ingestService
                .ingest(cbomUuid,
                        CbomIngestTestFixtures
                                .documentOf(CbomIngestTestFixtures.algorithmWithRef("AES-256", "aes-ref")),
                        OffsetDateTime.parse("2026-09-29T10:00:00Z"), CbomSyncPolicy.DEFAULTS))
                .isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
    }

    private static String endpoint(UUID uuid) {
        return "/v1/cboms/" + uuid + "/assets";
    }

    @Test
    void refusesWhenDetailAccessToTheCbomIsDenied() throws Exception {
        denyResourceAccess(Resource.CBOM, ResourceAction.DETAIL);

        mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'CBOM'")));
    }

    @Test
    void refusesWhenListingCryptographicAssetsIsDenied() throws Exception {
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.LIST);

        mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'Cryptographic Asset'")));
    }

    /** The CBOM lookup's own 404, told apart by its message from the one a request to no mapped route gets. */
    @Test
    void anUnknownCbomIsNotFound() throws Exception {
        UUID unknown = UUID.randomUUID();

        mockMvc
                .perform(post(endpoint(unknown)).contentType("application/json").content("{}"))
                .andExpectAll(status().isNotFound(), jsonPath("$.message")
                        .value(allOf(containsString("'Cbom'"), containsString(unknown.toString()))));
    }

    /**
     * The CBOM is looked up only after the asset gate, so a caller who may not list assets is refused by that gate
     * before an unknown CBOM could answer 404.
     */
    @Test
    void anUnknownCbomIsRefusedByTheAssetGateFirst() throws Exception {
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.LIST);
        UUID unknown = UUID.randomUUID();

        mockMvc
                .perform(post(endpoint(unknown)).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"),
                        jsonPath("$.message").value(containsString("'Cryptographic Asset'")));
    }

    @Test
    void servesTheRowsWithTheirRefsWithoutMentioningTheKey() throws Exception {
        String body = mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isOk(), jsonPath("$.totalItems").value(1),
                        jsonPath("$.items[0].name").value("aes-256"), jsonPath("$.items[0].sourceCbomCount").value(1),
                        jsonPath("$.items[0].bomRefs[0]").value("aes-ref"))
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(body).doesNotContainPattern(IDENTITY_KEY);
    }

    /**
     * Neither gate asks the authorization service while the request holds a database connection or a transaction: both
     * ask over HTTP, and whatever the request held across the call would wait as long as the service does. Over HTTP
     * the request's EntityManager is bound for open-in-view, and a read through it keeps its connection until the
     * response is written -- which only a test that runs through the request can see.
     */
    @Test
    void neitherGateIsAskedWhileTheRequestHoldsAConnection() throws Exception {
        Map<String, RequestState> stateOnVote = recordTheRequestsStateOnEachVote();

        mockMvc
                .perform(post(endpoint(cbomUuid)).contentType("application/json").content("{}"))
                .andExpectAll(status().isOk(), jsonPath("$.totalItems").value(1));

        assertThat(stateOnVote)
                .containsKeys(voteOn(Resource.CBOM, ResourceAction.DETAIL),
                        voteOn(Resource.CRYPTO_ASSET, ResourceAction.LIST))
                .allSatisfy((vote,
                        state) -> assertThat(state).describedAs(vote).isEqualTo(new RequestState(true, false, false)));
    }

    /**
     * What the request holds while a vote is asked. The EntityManager open-in-view binds is part of it, so the test
     * fails rather than passes should that binding ever be missing.
     */
    private record RequestState(boolean entityManagerBound, boolean connectionHeld, boolean transactionOpen) {

        private static RequestState now() {
            boolean bound = false;
            boolean connected = false;
            for (Object resource : TransactionSynchronizationManager.getResourceMap().values()) {
                if (resource instanceof EntityManagerHolder holder) {
                    bound = true;
                    connected |= holder
                            .getEntityManager()
                            .unwrap(SharedSessionContractImplementor.class)
                            .getJdbcCoordinator()
                            .getLogicalConnection()
                            .isPhysicallyConnected();
                }
            }
            return new RequestState(bound, connected, TransactionSynchronizationManager.isActualTransactionActive());
        }

        private RequestState and(RequestState later) {
            return new RequestState(entityManagerBound && later.entityManagerBound,
                    connectionHeld || later.connectionHeld, transactionOpen || later.transactionOpen);
        }
    }

    /** Grants every vote, as the default stubs do, and notes per resource and action what the request held on it. */
    private Map<String, RequestState> recordTheRequestsStateOnEachVote() {
        Map<String, RequestState> stateOnVote = new LinkedHashMap<>();
        OpaResourceAccessResult granted = new OpaResourceAccessResult();
        granted.setAuthorized(true);
        granted.setAllow(List.of());
        OpaObjectAccessResult everyObject = new OpaObjectAccessResult();
        everyObject.setActionAllowedForGroupOfObjects(true);
        everyObject.setAllowedObjects(List.of());
        everyObject.setForbiddenObjects(List.of());
        doAnswer(call -> {
            noteState(stateOnVote, call.getArgument(1));
            return granted;
        }).when(opaClient).checkResourceAccess(any(), any(), any(), any());
        doAnswer(call -> {
            noteState(stateOnVote, call.getArgument(1));
            return everyObject;
        }).when(opaClient).checkObjectAccess(any(), any(), any(), any());
        return stateOnVote;
    }

    private static void noteState(Map<String, RequestState> stateOnVote, OpaRequestedResource resource) {
        String vote = resource.getProperties().get("name") + "/" + resource.getProperties().get("action");
        stateOnVote.merge(vote, RequestState.now(), RequestState::and);
    }

    private static String voteOn(Resource resource, ResourceAction action) {
        return resource.getCode() + "/" + action.getCode();
    }
}
