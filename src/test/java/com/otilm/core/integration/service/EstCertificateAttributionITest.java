package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.certificate.CertificateSearchRequestDto;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.core.certificate.CertificateDetail;
import com.otilm.api.model.core.certificate.CertificateDto;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CertificateExternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.EstProfileRequestDtoBuilder.anEstProfileRequest;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyEqualsFilter;
import static org.assertj.core.api.Assertions.assertThat;

class EstCertificateAttributionITest extends BaseSpringBootTest {

    private static final String ORIGIN = "https://ilm.example.com";
    private static final String PROFILE_NAME = "est-devices";
    private static final String OWNER_NAME = "device-owner";

    @Autowired
    private EstProfileExternalService estProfileService;

    @Autowired
    private CertificateInternalService certificateInternalService;

    @Autowired
    private CertificateExternalService certificateService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private ScepProfileRepository scepProfileRepository;

    private WireMockServer authService;

    @BeforeEach
    void startAuthService() {
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
    }

    @AfterEach
    void stopAuthService() {
        authService.stop();
    }

    // ── ApplyProtocolAssociations ─────────────────────────────────────────────

    @Nested
    class ApplyProtocolAssociations {

        @Test
        void appliesProfileAssociations_whenCertificateIsAttributedToEstProfile() throws Exception {
            // given
            UUID owner = UUID.randomUUID();
            stubOwner(owner);
            Group group = saveGroup("device-operators");
            UUID profileUuid = createEstProfile(anEstProfileRequest()
                    .withName(PROFILE_NAME)
                    .withCertificateAssociations(buildAssociations(owner, group))
                    .build());
            Certificate certificate = saveCertificate();

            // when
            certificateInternalService
                    .applyProtocolAssociations(certificate.getUuid(), CertificateProtocolInfo.est(profileUuid));

            // then
            CertificateDetail attributed = certificateService.getCertificate(certificate.getSecuredUuid());
            assertThat(attributed.getOwnerUuid()).isEqualTo(owner.toString());
            assertThat(attributed.getOwner()).isEqualTo(OWNER_NAME);
            assertThat(attributed.getGroups())
                    .extracting(GroupDto::getUuid)
                    .containsExactly(group.getUuid().toString());
            assertThat(attributed.getProtocolInfo().getProtocol()).isEqualTo(CertificateProtocol.EST);
            assertThat(attributed.getProtocolInfo().getProtocolProfileUuid()).isEqualTo(profileUuid);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static ProtocolCertificateAssociationsRequestDto buildAssociations(UUID owner, Group group) {
            ProtocolCertificateAssociationsRequestDto associations = new ProtocolCertificateAssociationsRequestDto();
            associations.setOwnerUuid(owner);
            associations.setGroupUuids(List.of(group.getUuid()));
            return associations;
        }

        private Group saveGroup(String name) {
            Group group = new Group();
            group.setName(name);
            return groupRepository.save(group);
        }

        private void stubOwner(UUID owner) {
            authService
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/auth/users/" + owner))
                            .willReturn(WireMock
                                    .okJson("{\"uuid\": \"%s\", \"username\": \"%s\"}".formatted(owner, OWNER_NAME))));
        }
    }

    // ── ListCertificates ──────────────────────────────────────────────────────

    @Nested
    class ListCertificates {

        private Certificate throughEst;
        private Certificate throughScep;
        private Certificate unattributed;

        @BeforeEach
        void attributeCertificatesThroughEstAndScep() throws Exception {
            UUID estProfileUuid = createEstProfile(anEstProfileRequest().withName(PROFILE_NAME).build());
            // A profile of another protocol may carry the same name: only the EST attribution may match an EST Profile.
            UUID scepProfileUuid = saveScepProfile(PROFILE_NAME).getUuid();
            throughEst = saveCertificate();
            throughScep = saveCertificate();
            unattributed = saveCertificate();
            certificateInternalService
                    .applyProtocolAssociations(throughEst.getUuid(), CertificateProtocolInfo.est(estProfileUuid));
            certificateInternalService
                    .applyProtocolAssociations(throughScep.getUuid(), CertificateProtocolInfo.Scep(scepProfileUuid));
        }

        @Test
        void returnsEveryCertificate_whenNoFilterIsGiven() {
            // given — certificates attributed through EST, through SCEP under the same name, and through neither

            // when
            List<String> found = searchCertificates();

            // then
            assertThat(found)
                    .containsExactlyInAnyOrder(throughEst.getUuid().toString(), throughScep.getUuid().toString(),
                            unattributed.getUuid().toString());
        }

        @Test
        void returnsOnlyEstAttributedCertificates_whenFilteringByEstProfileName() {
            // given — certificates attributed through EST, through SCEP under the same name, and through neither

            // when
            List<String> found = searchCertificates(buildProfileNameFilter(FilterField.EST_PROFILE));

            // then
            assertThat(found).containsExactly(throughEst.getUuid().toString());
        }

        @Test
        void returnsOnlyScepAttributedCertificates_whenFilteringByTheSameNameUnderScep() {
            // given — certificates attributed through EST, through SCEP under the same name, and through neither

            // when
            List<String> found = searchCertificates(buildProfileNameFilter(FilterField.SCEP_PROFILE));

            // then
            assertThat(found)
                    .describedAs("the same name under SCEP finds the SCEP certificate, so the EST result left it out")
                    .containsExactly(throughScep.getUuid().toString());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static SearchFilterRequestDto buildProfileNameFilter(FilterField profileField) {
            return aPropertyEqualsFilter(profileField, new ArrayList<>(List.of(PROFILE_NAME)));
        }

        private List<String> searchCertificates(SearchFilterRequestDto... filters) {
            CertificateSearchRequestDto request = new CertificateSearchRequestDto();
            request.setPageNumber(1);
            request.setItemsPerPage(10);
            request.setFilters(List.of(filters));
            return certificateService
                    .listCertificates(SecurityFilter.create(), request)
                    .getCertificates()
                    .stream()
                    .map(CertificateDto::getUuid)
                    .toList();
        }
    }

    // ── GetSearchableFieldInformationByGroup ──────────────────────────────────

    @Nested
    class GetSearchableFieldInformationByGroup {

        @Test
        void offersEstProfileNames_whenEstProfilesExist() throws Exception {
            // given
            var otherProfileName = "est-gateways";
            stubUserList();
            createEstProfile(anEstProfileRequest().withName(PROFILE_NAME).build());
            createEstProfile(anEstProfileRequest().withName(otherProfileName).build());
            saveScepProfile("scep-devices");

            // when
            SearchFieldDataDto estProfileField = certificateService
                    .getSearchableFieldInformationByGroup()
                    .stream()
                    .flatMap(group -> group.getSearchFieldData().stream())
                    .filter(field -> FilterField.EST_PROFILE.name().equals(field.getFieldIdentifier()))
                    .findFirst()
                    .orElseThrow();

            // then
            assertThat(estProfileField.getFieldLabel()).isEqualTo("EST Profile");
            assertThat(estProfileField.getValue())
                    .asInstanceOf(InstanceOfAssertFactories.list(String.class))
                    .containsExactlyInAnyOrder(PROFILE_NAME, otherProfileName);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void stubUserList() {
            authService
                    .stubFor(WireMock
                            .get(WireMock.urlPathEqualTo("/auth/users"))
                            .willReturn(WireMock.okJson("{\"data\": []}")));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID createEstProfile(EstProfileRequestDto request) throws Exception {
        return UUID.fromString(estProfileService.createEstProfile(request, ORIGIN).getUuid());
    }

    private Certificate saveCertificate() {
        return certificateRepository.save(aCertificate().build());
    }

    private ScepProfile saveScepProfile(String name) {
        ScepProfile profile = new ScepProfile();
        profile.setName(name);
        return scepProfileRepository.save(profile);
    }
}
