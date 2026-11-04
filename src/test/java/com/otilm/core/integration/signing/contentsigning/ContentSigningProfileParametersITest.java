package com.otilm.core.integration.signing.contentsigning;

import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.SigningScheme;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.core.dao.entity.signing.SigningProfile;
import com.otilm.core.dao.entity.signing.SigningProfileVersion;
import com.otilm.core.dao.repository.signing.SigningProfileRepository;
import com.otilm.core.dao.repository.signing.SigningProfileVersionRepository;
import com.otilm.core.util.BaseSpringBootTest;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.annotation.Transactional;

import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.PadesVisibleSignatureDtoBuilder.aVisibleSignature;
import static com.otilm.core.util.builders.PadesVisibleSignaturePlacementDtoBuilder.aPlacement;
import static org.assertj.core.api.Assertions.assertThat;

@Transactional
class ContentSigningProfileParametersITest extends BaseSpringBootTest {

    private static final byte[] STAMP_BYTES = {(byte) 0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A};

    @Autowired
    private SigningProfileRepository signingProfileRepository;

    @Autowired
    private SigningProfileVersionRepository versionRepository;

    @PersistenceContext
    private EntityManager entityManager;

    @Test
    void keepsTheTypedDefaults_acrossTheJsonColumn() {
        // given — a version carrying nested PAdES defaults, saved and evicted
        SigningProfileVersion version = savedContentSigningVersion(padesDefaultsAcrossBothNestedContainers());

        // when — read back from the database
        SigningProfileVersion reloaded = versionRepository.findById(version.getUuid()).orElseThrow();

        // then — the discriminator and the value at each nesting depth are intact, image bytes included
        assertThat(reloaded.getDefaultSignatureParameters())
                .isInstanceOfSatisfying(PadesSignatureParametersDto.class, defaults -> {
                    assertThat(defaults.getFamily()).isEqualTo(SignatureFamily.PADES);
                    assertThat(defaults.getReason()).isEqualTo("Contract approval");
                    assertThat(defaults.getVisibleSignature().getImage()).isEqualTo(STAMP_BYTES);
                    assertThat(defaults.getVisibleSignature().getPlacement().getPage()).isEqualTo(1);
                });
    }

    @Test
    void keepsTheAllowList_acrossTheTextArrayColumn() {
        // given
        SigningProfileVersion version = savedContentSigningVersionWithGroups(List
                .of(SignatureParameterGroup.Codes.SIGNATURE_CONTEXT,
                        SignatureParameterGroup.Codes.VISIBLE_SIGNATURE_CONTENT));

        // when
        SigningProfileVersion reloaded = versionRepository.findById(version.getUuid()).orElseThrow();

        // then
        assertThat(reloaded.getAllowedRequestParameterGroups())
                .containsExactly(SignatureParameterGroup.Codes.SIGNATURE_CONTEXT,
                        SignatureParameterGroup.Codes.VISIBLE_SIGNATURE_CONTENT);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private SigningProfileVersion savedContentSigningVersion(PadesSignatureParametersDto defaults) {
        SigningProfileVersion version = newContentSigningVersion(List.of());
        version.setDefaultSignatureParameters(defaults);
        return persistAndEvict(version);
    }

    private SigningProfileVersion savedContentSigningVersionWithGroups(List<String> groupCodes) {
        return persistAndEvict(newContentSigningVersion(groupCodes));
    }

    private SigningProfileVersion newContentSigningVersion(List<String> groupCodes) {
        SigningProfile header = new SigningProfile();
        header.setName("content-signing-parameters-" + UUID.randomUUID());
        header.setSigningScheme(SigningScheme.MANAGED);
        header.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        header.setLatestVersion(1);
        signingProfileRepository.saveAndFlush(header);

        SigningProfileVersion version = new SigningProfileVersion();
        version.setSigningProfile(header);
        version.setVersion(1);
        version.setSigningScheme(SigningScheme.MANAGED);
        version.setManagedSigningType(ManagedSigningType.STATIC_KEY);
        version.setWorkflowType(SigningWorkflowType.CONTENT_SIGNING);
        version.setSignatureFamily(SignatureFamily.PADES);
        version.setAllowedRequestParameterGroups(new ArrayList<>(groupCodes));
        return version;
    }

    private SigningProfileVersion persistAndEvict(SigningProfileVersion version) {
        SigningProfileVersion saved = versionRepository.saveAndFlush(version);
        entityManager.clear();
        return saved;
    }

    /** One value at each nesting depth. */
    private static PadesSignatureParametersDto padesDefaultsAcrossBothNestedContainers() {
        return aPadesParameters()
                .withReason("Contract approval")
                .withVisibleSignature(
                        aVisibleSignature().withImage(STAMP_BYTES).withPlacement(aPlacement().withPage(1)))
                .build();
    }
}
