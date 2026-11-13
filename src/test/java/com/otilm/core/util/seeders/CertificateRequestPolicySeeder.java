package com.otilm.core.util.seeders;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.model.client.compliance.v2.ComplianceInternalRuleRequestDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.settings.SettingsSection;
import com.otilm.api.model.core.settings.SettingsSectionCategory;
import com.otilm.api.model.core.workflows.ConditionItemRequestDto;
import com.otilm.core.certificate.request.DefaultRequestAttributeSet;
import com.otilm.core.dao.entity.ComplianceProfile;
import com.otilm.core.dao.entity.ComplianceProfileRule;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.Setting;
import com.otilm.core.dao.repository.ComplianceProfileAssociationRepository;
import com.otilm.core.dao.repository.ComplianceProfileRepository;
import com.otilm.core.dao.repository.ComplianceProfileRuleRepository;
import com.otilm.core.dao.repository.SettingRepository;
import com.otilm.core.service.v2.ComplianceProfileExternalService;
import com.otilm.core.util.builders.ComplianceProfileFixtures;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Seeds the policies that the platform checks a certificate request against before it stores or issues it: the
 * strictness of the request-attribute policy, and a compliance profile of an RA Profile with one rule.
 */
@Component
public class CertificateRequestPolicySeeder {

    @Autowired
    private SettingRepository settingRepository;

    @Autowired
    private ComplianceProfileExternalService complianceProfileService;

    @Autowired
    private ComplianceProfileRepository complianceProfileRepository;

    @Autowired
    private ComplianceProfileAssociationRepository complianceAssociationRepository;

    @Autowired
    private ComplianceProfileRuleRepository complianceProfileRuleRepository;

    /**
     * Makes the request-attribute policy strict, so that a request which does not meet the request-attribute set of its
     * RA Profile, as one without a common name does not meet the default set, is refused before it is stored.
     */
    public void requireStrictRequestAttributes() {
        Setting strict = new Setting();
        strict.setSection(SettingsSection.PLATFORM);
        strict.setCategory(SettingsSectionCategory.PLATFORM_CERTIFICATES.getCode());
        strict.setName(DefaultRequestAttributeSet.STRICT_SETTING_NAME);
        strict.setValue("true");
        settingRepository.save(strict);
    }

    /**
     * Gives the RA Profile a compliance profile whose rule wants requests with an RSA key, so that a request with
     * another key makes the certificate that it asks for rejected once it is stored.
     */
    public void requireRsaRequests(RaProfile raProfile) throws AlreadyExistException {
        ConditionItemRequestDto condition = new ConditionItemRequestDto();
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier("CERT_REQUEST_PUBLIC_KEY_ALGORITHM");
        condition.setOperator(FilterConditionOperator.EQUALS);
        condition.setValue(List.of("RSA"));
        ComplianceInternalRuleRequestDto rule = new ComplianceInternalRuleRequestDto();
        rule.setName("rsa-requests");
        rule.setResource(Resource.CERTIFICATE_REQUEST);
        rule.setConditionItems(List.of(condition));
        UUID ruleUuid = complianceProfileService.createComplianceInternalRule(rule).getUuid();

        ComplianceProfile profile = ComplianceProfileFixtures
                .associateNewComplianceProfile(complianceProfileRepository, complianceAssociationRepository,
                        Resource.RA_PROFILE, raProfile.getUuid());
        ComplianceProfileRule profileRule = new ComplianceProfileRule();
        profileRule.setComplianceProfile(profile);
        profileRule.setComplianceProfileUuid(profile.getUuid());
        profileRule.setResource(Resource.CERTIFICATE_REQUEST);
        profileRule.setInternalRuleUuid(ruleUuid);
        complianceProfileRuleRepository.save(profileRule);
    }
}
