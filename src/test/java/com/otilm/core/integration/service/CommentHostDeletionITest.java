package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.certificate.RemoveCertificateDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CommentableHostObjects;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.mockbeans.ProducerMocks;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Deleting a commented object must leave no orphaned comment rows, on every commentable resource. APPROVAL is the one
 * exception: the platform has no approval delete path at all (approvals only transition status), so its threads cannot
 * be orphaned by deletion.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class CommentHostDeletionITest extends BaseSpringBootTest {

    @Autowired
    private ApplicationContext applicationContext;

    @Autowired
    private CommentRepository commentRepository;

    @Autowired
    private CertificateExternalService certificateService;

    private CommentableHostObjects hostObjects;

    private WireMockServer entityProviderMock;

    @BeforeEach
    void setUp() {
        hostObjects = new CommentableHostObjects(applicationContext);

        entityProviderMock = new WireMockServer(LoopbackWireMock.options());
        entityProviderMock.start();
        entityProviderMock
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/entityProvider/entities/.*"))
                        .willReturn(WireMock.noContent()));
        hostObjects.setEntityConnectorUrl(LoopbackWireMock.url(entityProviderMock));
    }

    @AfterEach
    void tearDown() {
        entityProviderMock.stop();
    }

    static Stream<Resource> deletableCommentableResources() {
        return Resource.getCommentableResources().stream().filter(resource -> resource != Resource.APPROVAL);
    }

    private Comment newComment(Resource resource, UUID objectUuid, UUID parentUuid) {
        Comment comment = new Comment();
        comment.setResource(resource);
        comment.setObjectUuid(objectUuid);
        comment.setParentUuid(parentUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("tst-user");
        comment.setBody("thread on a soon-deleted object");
        return comment;
    }

    @ParameterizedTest
    @MethodSource("deletableCommentableResources")
    void deletingTheHostObjectRemovesItsThreads(Resource resource) throws Exception {
        UUID objectUuid = hostObjects.create(resource);
        Comment root = commentRepository.saveAndFlush(newComment(resource, objectUuid, null));
        commentRepository.saveAndFlush(newComment(resource, objectUuid, root.getUuid()));

        hostObjects.deleteThroughService(resource, objectUuid);

        assertThat(commentRepository.existsByResourceAndObjectUuid(resource, objectUuid))
                .as("comments of %s %s survive its deletion", resource, objectUuid)
                .isFalse();
    }

    @Test
    void bulkDeletingCertificatesRemovesTheirThreads() throws Exception {
        List<UUID> deletedUuids = List
                .of(hostObjects.create(Resource.CERTIFICATE), hostObjects.create(Resource.CERTIFICATE));
        UUID keptUuid = hostObjects.create(Resource.CERTIFICATE);
        for (UUID objectUuid : List.of(deletedUuids.get(0), deletedUuids.get(1), keptUuid)) {
            Comment root = commentRepository.saveAndFlush(newComment(Resource.CERTIFICATE, objectUuid, null));
            commentRepository.saveAndFlush(newComment(Resource.CERTIFICATE, objectUuid, root.getUuid()));
        }

        RemoveCertificateDto request = new RemoveCertificateDto();
        request.setUuids(deletedUuids.stream().map(UUID::toString).toList());
        certificateService.bulkDeleteCertificate(SecurityFilter.create(), request);

        for (UUID objectUuid : deletedUuids) {
            assertThat(commentRepository.existsByResourceAndObjectUuid(Resource.CERTIFICATE, objectUuid))
                    .as("comments of certificate %s survive its bulk deletion", objectUuid)
                    .isFalse();
        }
        assertThat(commentRepository.existsByResourceAndObjectUuid(Resource.CERTIFICATE, keptUuid))
                .as("comments of certificate %s left out of the bulk deletion", keptUuid)
                .isTrue();
    }
}
