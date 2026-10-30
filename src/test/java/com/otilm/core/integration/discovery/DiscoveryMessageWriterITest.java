package com.otilm.core.integration.discovery;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryMessageSeverity;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.DiscoveryMessage;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryMessageRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.model.discovery.DiscoveryMessageCode;
import com.otilm.core.model.discovery.DiscoveryMessageDraft;
import com.otilm.core.service.writer.discovery.DiscoveryMessageWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.DiscoveryInterfaceFixture;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * What a run's message log does under repetition and under pressure, against real PostgreSQL: the upsert has to
 * aggregate rather than accumulate, the bounds have to hold without evicting what an operator came for, and the order
 * has to survive a tick that writes several messages inside one transaction.
 *
 * <p>
 * The writer is built here rather than autowired, with bounds low enough that overflow is reachable. Setting those
 * through {@code @TestPropertySource} would fork a second Spring context for this one class; the bean's own wiring is
 * exercised by every other discovery ITest, and its transaction semantics do not enter into it — the test's transaction
 * is the ambient one either way.
 */
@Transactional
class DiscoveryMessageWriterITest extends BaseSpringBootTest {

    private static final int MAX_PER_CODE = 3;
    private static final int MAX_PER_RUN = 5;
    private static final int MAX_LENGTH = 40;

    private DiscoveryMessageWriter writer;

    @Autowired
    private DiscoveryMessageRepository messageRepository;
    @Autowired
    private DiscoveryRepository discoveryRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @PersistenceContext
    private EntityManager entityManager;

    @BeforeEach
    void setUp() {
        writer = new DiscoveryMessageWriter(messageRepository, MAX_PER_CODE, MAX_PER_RUN, MAX_LENGTH);
    }

    @Test
    void theSameProblemTwice_aggregatesOntoOneRowRatherThanAddingASecond() {
        Discovery run = v2Run();

        writer.append(run.getUuid(), gap("the host refused the connection", 3));
        writer.append(run.getUuid(), gap("the host refused the connection", 4));

        assertThat(messages(run)).singleElement().satisfies(message -> {
            assertThat(message.getOccurrences())
                    .as("the counts add: a batch reporting the same gap must not overwrite the one before it")
                    .isEqualTo(7);
            assertThat(message.getLastSeenAt()).isAfterOrEqualTo(message.getFirstSeenAt());
        });
    }

    @Test
    void sameTextUnderADifferentCode_isADifferentProblem() {
        Discovery run = v2Run();

        writer.append(run.getUuid(), gap("could not be staged", 1));
        writer
                .append(run.getUuid(), new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING,
                        DiscoveryMessageCode.CERTIFICATE_STAGING_FAILED, "could not be staged", 1));

        assertThat(messages(run)).hasSize(2);
    }

    @Test
    void distinctProblemsPastThePerCodeBound_foldIntoOneSuppressionRowAndLeaveTheOldestAlone() {
        Discovery run = v2Run();

        for (int i = 1; i <= 6; i++) {
            writer.append(run.getUuid(), gap("failure number " + i, 1));
        }

        List<DiscoveryMessage> log = messages(run);
        assertThat(log).hasSize(4);
        assertThat(log)
                .extracting(DiscoveryMessage::getMessage)
                .as("the oldest three survive: an operator opening a degraded run is looking for what started it")
                .startsWith("failure number 1", "failure number 2", "failure number 3");
        assertThat(log.get(3).getOccurrences())
                .as("the three it had no room for are counted rather than lost silently")
                .isEqualTo(3);
        assertThat(log.get(3).getCode())
                .as("suppression is per code, so what was dropped is still attributable")
                .isEqualTo(DiscoveryMessageCode.INVENTORY_GAP.code());
    }

    @Test
    void aSuppressionRow_countsTheOccurrencesItStandsInForRatherThanTheMessages() {
        Discovery run = v2Run();
        for (int i = 1; i <= MAX_PER_CODE; i++) {
            writer.append(run.getUuid(), gap("failure number " + i, 1));
        }

        writer.append(run.getUuid(), gap("a kind with no room left", 5));

        assertThat(messages(run)).last().satisfies(suppressed -> {
            assertThat(suppressed.getOccurrences())
                    .as("five occurrences went unrecorded, not one message")
                    .isEqualTo(5);
            assertThat(suppressed.getSeverity())
                    .as("a run that lost information about itself is at least a warning")
                    .isEqualTo(DiscoveryMessageSeverity.WARNING);
        });
    }

    @Test
    void aRepeatOfSomethingAlreadyRecorded_landsEvenOnceTheBoundIsReached() {
        Discovery run = v2Run();
        for (int i = 1; i <= 4; i++) {
            writer.append(run.getUuid(), gap("failure number " + i, 1));
        }

        writer.append(run.getUuid(), gap("failure number 1", 5));

        assertThat(messages(run))
                .filteredOn(message -> "failure number 1".equals(message.getMessage()))
                .singleElement()
                .satisfies(message -> assertThat(message.getOccurrences()).isEqualTo(6));
    }

    @Test
    void aFullRun_foldsEveryFurtherKindIntoASingleRow() {
        Discovery run = v2Run();
        // Three of one kind fills that code; codes minted per problem then fill the run.
        for (int i = 1; i <= 3; i++) {
            writer.append(run.getUuid(), gap("failure number " + i, 1));
        }
        for (int i = 1; i <= 6; i++) {
            writer
                    .append(run.getUuid(), new DiscoveryMessageDraft(DiscoveryMessageSeverity.ERROR,
                            "connectorCode" + i, "the connector reported a problem", 1));
        }

        List<DiscoveryMessage> log = messages(run);
        assertThat(log)
                .extracting(DiscoveryMessage::getCode)
                .as("a connector minting a fresh code per error cannot grow the log one suppression row at a time")
                .filteredOn(DiscoveryMessageCode.MESSAGES_SUPPRESSED.code()::equals)
                .hasSize(1);
        // Three of the first kind, the two connector codes that fitted, and the one row standing in for the rest.
        assertThat(log).hasSize(6);
    }

    @Test
    void howARunEnded_landsOnARunThatIsAlreadyFull() {
        Discovery run = v2Run();
        for (int i = 1; i <= 9; i++) {
            writer
                    .append(run.getUuid(),
                            new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING, "code" + i, "a problem", 1));
        }

        writer.appendRunEnded(run.getUuid(), DiscoveryMessageSeverity.WARNING, "Discovery completed with warnings.");

        assertThat(messages(run))
                .extracting(DiscoveryMessage::getCode)
                .as("a run's ending is the one message an operator is guaranteed to look for")
                .contains(DiscoveryMessageCode.RUN_ENDED.code());
    }

    @Test
    void messagesWrittenInOneTransaction_comeBackInTheOrderTheyWereWritten() {
        Discovery run = v2Run();

        // now() is transaction-start time, so all four share a timestamp to the microsecond. Only the identity
        // column separates them, which is why the listing orders by it.
        for (int i = 1; i <= 4; i++) {
            writer
                    .append(run.getUuid(),
                            new DiscoveryMessageDraft(DiscoveryMessageSeverity.INFO, "code" + i, "problem " + i, 1));
        }

        List<DiscoveryMessage> log = messages(run);
        assertThat(log)
                .extracting(DiscoveryMessage::getMessage)
                .containsExactly("problem 1", "problem 2", "problem 3", "problem 4");
        assertThat(log)
                .extracting(DiscoveryMessage::getFirstSeenAt)
                .as("the timestamps tie, which is what makes them useless as an order")
                .containsOnly(log.getFirst().getFirstSeenAt());
    }

    @Test
    void messageLongerThanTheBound_isShortenedAndSaysSo() {
        Discovery run = v2Run();

        writer.append(run.getUuid(), gap("x".repeat(200), 1));

        assertThat(messages(run)).singleElement().satisfies(message -> {
            assertThat(message.getMessage()).hasSize(MAX_LENGTH).endsWith("...");
        });
    }

    @Test
    void deletingTheRun_takesItsMessagesWithIt() {
        Discovery run = v2Run();
        writer.append(run.getUuid(), gap("the host refused the connection", 1));
        entityManager.flush();

        discoveryRepository.delete(run);
        entityManager.flush();
        entityManager.clear();

        assertThat(messageRepository.countByDiscoveryUuid(run.getUuid())).isZero();
    }

    private static DiscoveryMessageDraft gap(String message, long occurrences) {
        return new DiscoveryMessageDraft(DiscoveryMessageSeverity.WARNING, DiscoveryMessageCode.INVENTORY_GAP, message,
                occurrences);
    }

    private List<DiscoveryMessage> messages(Discovery run) {
        entityManager.flush();
        entityManager.clear();
        return messageRepository.findByDiscoveryUuidOrderByIdAsc(run.getUuid());
    }

    private Discovery v2Run() {
        Discovery run = new Discovery();
        run.setName("v2-scan-" + UUID.randomUUID());
        run.setKind("IP-HostName");
        run.setStatus(DiscoveryStatus.IN_PROGRESS);
        run.setConnectorStatus(DiscoveryStatus.IN_PROGRESS);
        ConnectorInterfaceEntity discoveryInterface = DiscoveryInterfaceFixture
                .v2Interface(connectorRepository, connectorInterfaceRepository);
        run.setConnectorUuid(discoveryInterface.getConnectorUuid());
        run.setConnectorName("network-discovery");
        run.setConnectorInterfaceUuid(discoveryInterface.getUuid());
        run.setResources(List.of(Resource.CERTIFICATE));
        return discoveryRepository.saveAndFlush(run);
    }
}
