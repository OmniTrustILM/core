package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.RaProfileProtocolAttributeRepository;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.EstCsrFixtures;
import java.security.Security;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstIssueRequestsTest {

    @Mock
    private AttributeEngine attributeEngine;

    @Mock
    private RaProfileProtocolAttributeRepository protocolAttributeRepository;

    private EstIssueRequests requests;
    private static final String V3_ACTIVATION_ATTRIBUTE = """
            [{"uuid":"6a8b2c4d-0e9f-4f13-a7d5-58c3b1e2f903","name":"validity_days","description":"d","version":3,\
            "type":"data","content":[{"reference":null,"data":365,"contentType":"integer"}],"contentType":"integer",\
            "properties":{"label":"Validity (days)","visible":true,"group":null,"required":true,"readOnly":false,\
            "list":false,"multiSelect":false,"protectionLevel":"none","resource":null,"extensibleList":false},\
            "schemaVersion":"v3"}]""";

    private Pkcs10CertificateRequest csr;
    private byte[] encodedCsr;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @BeforeEach
    void createRequests() throws Exception {
        requests = new EstIssueRequests(attributeEngine, protocolAttributeRepository);
        encodedCsr = Base64.getDecoder().decode(EstCsrFixtures.signedRequestBody());
        csr = new Pkcs10CertificateRequest(encodedCsr);
    }

    @Test
    void carriesTheRequestAsBase64Pkcs10_whenBuildingANewRequest() {
        // given
        EstRoute route = raProfileRoute();

        // when
        ClientCertificateIssueRequestDto request = requests.newRequest(route, csr);

        // then
        assertThat(request.getRequest()).isEqualTo(Base64.getEncoder().encodeToString(encodedCsr));
        assertThat(request.getFormat()).isEqualTo(CertificateRequestFormat.PKCS10);
        assertThat(request.getAuthorizationSecret()).isNull();
    }

    @Test
    void carriesTheSecret_whenBuildingACompletionRequest() {
        // given
        EstRoute route = raProfileRoute();

        // when
        ClientCertificateIssueRequestDto request = requests.completionRequest(route, csr, "challenge");

        // then
        assertThat(request.getRequest()).isEqualTo(Base64.getEncoder().encodeToString(encodedCsr));
        assertThat(request.getAuthorizationSecret()).isEqualTo("challenge");
    }

    @Test
    void readsNoAttributeEngine_whenRouteNamesRaProfile() {
        // given
        EstRoute route = raProfileRoute();

        // when
        List<RequestAttribute> attributes = requests.issueAttributes(route);

        // then
        assertThat(attributes).isEmpty();
        verifyNoInteractions(attributeEngine);
    }

    @Test
    void readsTheEstActivationAttributesByQuery_whenRouteNamesRaProfile() {
        // given
        EstRoute route = raProfileRoute();
        var activationAttributeName = "profileName";
        when(protocolAttributeRepository.findEstIssueCertificateAttributesByRaProfileUuid(route.raProfile().getUuid()))
                .thenReturn(Optional.of(serializedActivationAttribute(activationAttributeName, "devices")));

        // when
        List<RequestAttribute> attributes = requests.issueAttributes(route);

        // then
        assertThat(attributes).extracting(RequestAttribute::getName).containsExactly(activationAttributeName);
    }

    @Test
    void readsAV3ActivationAttribute_whenRouteNamesRaProfile() {
        // given
        EstRoute route = raProfileRoute();
        when(protocolAttributeRepository.findEstIssueCertificateAttributesByRaProfileUuid(route.raProfile().getUuid()))
                .thenReturn(Optional.of(V3_ACTIVATION_ATTRIBUTE));

        // when
        List<RequestAttribute> attributes = requests.issueAttributes(route);

        // then
        assertThat(attributes).extracting(RequestAttribute::getName).containsExactly("validity_days");
        assertThat(((RequestAttributeV3) attributes.getFirst()).getContent().getFirst().getData()).isEqualTo(365);
    }

    /** The RA Profile carries no protocol attribute, as one read without its lazy association does. */
    private static EstRoute raProfileRoute() {
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        EstProfile estProfile = anEstProfile().withUuid(UUID.randomUUID()).build();
        return new EstRoute(estProfile, raProfile, true, "devices-ra");
    }

    private static String serializedActivationAttribute(String name, String value) {
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(UUID.randomUUID().toString());
        attribute.setName(name);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value)));
        return AttributeDefinitionUtils.serialize(List.of(attribute));
    }
}
