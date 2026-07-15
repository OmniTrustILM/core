package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.attribute.v2.InfoAttributeV2;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import org.junit.jupiter.api.Test;

import java.util.List;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class IssuanceDefinitionResolverTest {

    private final RaProfileCertificateRequestAttributeService requestAttributeService =
            mock(RaProfileCertificateRequestAttributeService.class);
    private final IssuanceDefinitionResolver resolver = new IssuanceDefinitionResolver(requestAttributeService);

    @Test
    void resolvesConfiguredSet_keepingOnlyV3Definitions() throws Exception {
        // given — the shared resolver returns a v3 definition mixed with a non-v3 legacy one
        RaProfile raProfile = new RaProfile();
        DataAttributeV3 department = aMappedDataAttribute().withName("department").mappingRdn("OU").build();
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        doReturn(List.of(department, legacy)).when(requestAttributeService).resolveIssueAttributeSet(raProfile);

        // when
        List<DataAttributeV3> resolved = resolver.resolve(raProfile);

        // then — the projection consumes the configured set; non-v3 definitions cannot carry a fieldMapping and are dropped
        assertThat(resolved).containsExactly(department);
    }

    @Test
    void fallsBackToDefaultSet_whenResolvedSetHasNoV3Definitions() throws Exception {
        // given — a v2 authority connector supplies the whole resolved set, so no definition is v3
        RaProfile raProfile = new RaProfile();
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        doReturn(List.of(legacy)).when(requestAttributeService).resolveIssueAttributeSet(raProfile);
        DataAttributeV3 fqdn = aMappedDataAttribute().withName("fqdn").mappingRdn("CN").build();
        InfoAttributeV2 legacyDefault = new InfoAttributeV2();
        legacyDefault.setName("legacy-default");
        doReturn(List.of(fqdn, legacyDefault)).when(requestAttributeService).getDefaultSet(raProfile);

        // when
        List<DataAttributeV3> resolved = resolver.resolve(raProfile);

        // then — the platform default set shapes the projection instead of resolving empty
        assertThat(resolved).containsExactly(fqdn);
    }

    @Test
    void rejectsResolution_whenResolvedSetIsEmpty() throws Exception {
        // given — the shared resolver resolves to nothing at all (no static set, no connector set, empty default)
        RaProfile raProfile = new RaProfile();
        raProfile.setName("empty-profile");
        doReturn(List.of()).when(requestAttributeService).resolveIssueAttributeSet(raProfile);

        // when / then — the empty resolved set skips the default-set fallback and fails loudly; the default set is never consulted
        assertThatThrownBy(() -> resolver.resolve(raProfile))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("empty-profile")
                .hasMessageContaining("request attribute");
        verify(requestAttributeService, never()).getDefaultSet(raProfile);
    }

    @Test
    void rejectsResolution_whenNoV3DefinitionsInResolvedOrDefaultSet() throws Exception {
        // given — neither the resolved set nor the platform default set carries a v3 definition
        RaProfile raProfile = new RaProfile();
        raProfile.setName("v2-profile");
        InfoAttributeV2 legacy = new InfoAttributeV2();
        legacy.setName("legacy-info");
        doReturn(List.of(legacy)).when(requestAttributeService).resolveIssueAttributeSet(raProfile);
        InfoAttributeV2 legacyDefault = new InfoAttributeV2();
        legacyDefault.setName("legacy-default");
        doReturn(List.of(legacyDefault)).when(requestAttributeService).getDefaultSet(raProfile);

        // when / then — fail loudly instead of letting the build path produce an identity-less request
        assertThatThrownBy(() -> resolver.resolve(raProfile))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("v2-profile")
                .hasMessageContaining("request attribute");
    }

    @Test
    void rejectsNullRaProfile() {
        // when / then — both build paths always carry a profile; a null profile is a caller bug, not a fallback
        assertThatNullPointerException().isThrownBy(() -> resolver.resolve(null));
        verifyNoInteractions(requestAttributeService);
    }
}
