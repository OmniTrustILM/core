package com.czertainly.core.mapper.certificate;

import com.czertainly.api.model.client.raprofile.SimplifiedRaProfileDto;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.certificate.*;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.api.model.core.cryptography.key.KeyState;
import com.czertainly.api.model.core.enums.CertificateProtocol;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.core.dao.entity.*;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.Set;
import java.util.UUID;

class CertificateDetailDtoMapperTest {

    private Certificate certificate;

    @BeforeEach
    void setUp() {
        certificate = new Certificate();
        certificate.uuid = UUID.randomUUID();
        certificate.setCommonName("test.example.com");
        certificate.setCertificateType(CertificateType.X509);
        certificate.setState(CertificateState.ISSUED);
        certificate.setSubjectDn("CN=test.example.com");
        certificate.setIssuerCommonName("Example CA");
        certificate.setIssuerDn("CN=Example CA");
        certificate.setSerialNumber("0123456789abcdef");
        certificate.setFingerprint("aa:bb:cc");
        certificate.setPublicKeyAlgorithm("RSA");
        certificate.setAltPublicKeyAlgorithm("ML-DSA");
        certificate.setSignatureAlgorithm("SHA256withRSA");
        certificate.setAltSignatureAlgorithm("ML-DSA");
        certificate.setNotBefore(new Date(1_000_000_000L));
        certificate.setNotAfter(new Date(2_000_000_000L));
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toDetailDto
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toDetailDto_mapsAllFieldsIncludingConditionals() throws NoSuchAlgorithmException {
        // certificateContent branch
        CertificateContent content = new CertificateContent();
        content.setContent("base64encodedcert==");
        certificate.setCertificateContent(content);

        // QC statements branch (all four sub-fields to cover qcType and qcCcLegislation branches)
        certificate.setQcCompliance(true);
        certificate.setQcSscd(true);
        certificate.setQcType("[\"ESIGN\"]");
        certificate.setQcCcLegislation("[\"CZ\"]");

        // issuerCertificateUuid branch
        UUID issuerUuid = UUID.randomUUID();
        certificate.setIssuerCertificateUuid(issuerUuid);

        // predecessorRelations branch (sourceCertificateUuid)
        Certificate predecessor = new Certificate();
        predecessor.uuid = UUID.randomUUID();
        CertificateRelation relation = new CertificateRelation();
        relation.setPredecessorCertificate(predecessor);
        certificate.setPredecessorRelations(Set.of(relation));

        // owner branch
        OwnerAssociation owner = new OwnerAssociation();
        owner.setOwnerUuid(UUID.randomUUID());
        owner.setOwnerUsername("alice");
        certificate.setOwner(owner);

        // raProfile branch
        RaProfile raProfile = new RaProfile();
        raProfile.uuid = UUID.randomUUID();
        raProfile.setName("test-ra");
        raProfile.setEnabled(true);
        certificate.setRaProfile(raProfile);

        // groups branch
        Group group = new Group();
        group.uuid = UUID.randomUUID();
        group.setName("test-group");
        certificate.setGroups(Set.of(group));

        // certificateRequest branch (with keyUuid and altKeyUuid to cover their sub-branches)
        CertificateRequestEntity request = new CertificateRequestEntity();
        request.uuid = UUID.randomUUID();
        request.setContent("csrContent");
        request.setCertificateType(CertificateType.X509);
        request.setCommonName("test.example.com");
        request.setSubjectDn("CN=test.example.com");
        request.setSignatureAlgorithm("SHA256withRSA");
        request.setAltSignatureAlgorithm("ML-DSA");
        request.setPublicKeyAlgorithm("RSA");
        request.setCertificateRequestFormat(CertificateRequestFormat.PKCS10);
        request.setKeyUuid(UUID.randomUUID());
        request.setAltKeyUuid(UUID.randomUUID());
        request.setComplianceStatus(ComplianceStatus.NOT_CHECKED);
        certificate.setCertificateRequest(request);

        // key branch — include an ACTIVE PRIVATE_KEY item to hit privateKeyAvailability=true
        CryptographicKey key = new CryptographicKey();
        key.uuid = UUID.randomUUID();
        key.setName("test-key");
        CryptographicKeyItem privateKeyItem = new CryptographicKeyItem();
        privateKeyItem.uuid = UUID.randomUUID();
        privateKeyItem.setType(KeyType.PRIVATE_KEY);
        privateKeyItem.setState(KeyState.ACTIVE);
        privateKeyItem.setKey(key);
        key.setItems(Set.of(privateKeyItem));
        certificate.setKey(key);

        // altKey branch
        CryptographicKey altKey = new CryptographicKey();
        altKey.uuid = UUID.randomUUID();
        altKey.setName("alt-key");
        certificate.setAltKey(altKey);

        // protocolAssociation branch
        CertificateProtocolAssociation protocol = new CertificateProtocolAssociation();
        protocol.setProtocol(CertificateProtocol.ACME);
        UUID protocolProfileUuid = UUID.randomUUID();
        UUID additionalProtocolUuid = UUID.randomUUID();
        protocol.setProtocolProfileUuid(protocolProfileUuid);
        protocol.setAdditionalProtocolUuid(additionalProtocolUuid);
        certificate.setProtocolAssociation(protocol);

        certificate.setComplianceStatus(ComplianceStatus.OK);

        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        // flat fields
        Assertions.assertEquals(certificate.uuid.toString(),    dto.getUuid());
        Assertions.assertEquals("test.example.com",             dto.getCommonName());
        Assertions.assertEquals("Example CA",                   dto.getIssuerCommonName());
        Assertions.assertEquals("CN=test.example.com",          dto.getSubjectDn());
        Assertions.assertEquals("RSA",                          dto.getPublicKeyAlgorithm());
        Assertions.assertEquals("ML-DSA",                       dto.getAltPublicKeyAlgorithm());
        Assertions.assertEquals("SHA256withRSA",                dto.getSignatureAlgorithm());
        Assertions.assertEquals("ML-DSA",                       dto.getAltSignatureAlgorithm());
        Assertions.assertEquals(CertificateState.ISSUED,        dto.getState());
        Assertions.assertEquals(CertificateType.X509,           dto.getCertificateType());
        Assertions.assertEquals(ComplianceStatus.OK,            dto.getComplianceStatus());
        // certificateContent branch
        Assertions.assertEquals("base64encodedcert==",          dto.getCertificateContent());
        Assertions.assertEquals("CN=Example CA",                dto.getIssuerDn());
        Assertions.assertEquals("0123456789abcdef",             dto.getSerialNumber());
        Assertions.assertEquals("aa:bb:cc",                     dto.getFingerprint());
        // QC statements branch
        CertificateQcStatementsDto qc = dto.getQcStatements();
        Assertions.assertNotNull(qc);
        Assertions.assertTrue(qc.getQcCompliance());
        Assertions.assertTrue(qc.getQcSscd());
        Assertions.assertEquals(1, qc.getQcType().size());
        Assertions.assertEquals(QcType.ESIGN, qc.getQcType().getFirst());
        Assertions.assertEquals(1, qc.getQcCcLegislation().size());
        Assertions.assertEquals("CZ", qc.getQcCcLegislation().getFirst());
        // issuerCertificateUuid branch
        Assertions.assertEquals(issuerUuid.toString(),          dto.getIssuerCertificateUuid());
        // predecessorRelations branch
        Assertions.assertEquals(predecessor.uuid,               dto.getSourceCertificateUuid());
        // owner branch
        Assertions.assertEquals(owner.getOwnerUuid().toString(), dto.getOwnerUuid());
        Assertions.assertEquals("alice",                        dto.getOwner());
        // raProfile branch
        SimplifiedRaProfileDto raDto = dto.getRaProfile();
        Assertions.assertNotNull(raDto);
        Assertions.assertEquals(raProfile.uuid.toString(),      raDto.getUuid());
        Assertions.assertEquals("test-ra",                      raDto.getName());
        // groups branch
        Assertions.assertEquals(1, dto.getGroups().size());
        Assertions.assertEquals(group.uuid.toString(),          dto.getGroups().getFirst().getUuid());
        // certificateRequest branch
        CertificateRequestDto reqDto = dto.getCertificateRequest();
        Assertions.assertNotNull(reqDto);
        Assertions.assertEquals(request.uuid,                   reqDto.getUuid());
        Assertions.assertEquals(request.getKeyUuid().toString(), reqDto.getKeyUuid());
        Assertions.assertEquals(request.getAltKeyUuid().toString(), reqDto.getAltKeyUuid());
        // privateKeyAvailability branch
        Assertions.assertTrue(dto.isPrivateKeyAvailability());
        // key branch
        Assertions.assertNotNull(dto.getKey());
        Assertions.assertEquals(key.uuid.toString(),            dto.getKey().getUuid());
        // altKey branch
        Assertions.assertNotNull(dto.getAltKey());
        Assertions.assertEquals(altKey.uuid.toString(),         dto.getAltKey().getUuid());
        // protocolAssociation branch
        CertificateProtocolDto protocolDto = dto.getProtocolInfo();
        Assertions.assertNotNull(protocolDto);
        Assertions.assertEquals(CertificateProtocol.ACME,      protocolDto.getProtocol());
        Assertions.assertEquals(protocolProfileUuid,            protocolDto.getProtocolProfileUuid());
        Assertions.assertEquals(additionalProtocolUuid,         protocolDto.getAdditionalProtocolUuid());
    }

    @Test
    void toDetailDto_qcStatements_nullWhenExtensionAbsent() {
        CertificateContent content = new CertificateContent();
        content.setContent("base64cert==");
        certificate.setCertificateContent(content);

        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);
        Assertions.assertNull(dto.getQcStatements());
    }

    @Test
    void toDetailDto_qcStatements_emittedWhenAllFlagsAreFalse() {
        CertificateContent content = new CertificateContent();
        content.setContent("base64cert==");
        certificate.setCertificateContent(content);
        certificate.setQcCompliance(false);
        certificate.setQcSscd(false);

        CertificateDetailDto dto = CertificateDetailDtoMapper.toDetailDto(certificate);

        CertificateQcStatementsDto qc = dto.getQcStatements();
        Assertions.assertNotNull(qc, "qcStatements must be emitted even when qcCompliance and qcSscd are both false");
        Assertions.assertFalse(qc.getQcCompliance());
        Assertions.assertFalse(qc.getQcSscd());
        Assertions.assertNull(qc.getQcType());
        Assertions.assertNull(qc.getQcCcLegislation());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toListDto
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toListDto_mapsAllFieldsIncludingConditionals() {
        UUID issuerUuid = UUID.randomUUID();
        certificate.setIssuerCertificateUuid(issuerUuid);

        OwnerAssociation owner = new OwnerAssociation();
        owner.setOwnerUuid(UUID.randomUUID());
        owner.setOwnerUsername("alice");
        certificate.setOwner(owner);

        RaProfile raProfile = new RaProfile();
        raProfile.uuid = UUID.randomUUID();
        raProfile.setName("test-ra");
        raProfile.setEnabled(true);
        certificate.setRaProfile(raProfile);

        certificate.setComplianceStatus(ComplianceStatus.OK);

        CertificateDto dto = CertificateDetailDtoMapper.toListDto(certificate);

        Assertions.assertEquals(certificate.uuid.toString(),  dto.getUuid());
        Assertions.assertEquals("test.example.com",           dto.getCommonName());
        Assertions.assertEquals("Example CA",                 dto.getIssuerCommonName());
        Assertions.assertEquals("0123456789abcdef",           dto.getSerialNumber());
        Assertions.assertEquals("CN=Example CA",              dto.getIssuerDn());
        Assertions.assertEquals("CN=test.example.com",        dto.getSubjectDn());
        Assertions.assertEquals("aa:bb:cc",                   dto.getFingerprint());
        Assertions.assertEquals("RSA",                        dto.getPublicKeyAlgorithm());
        Assertions.assertEquals("ML-DSA",                     dto.getAltPublicKeyAlgorithm());
        Assertions.assertEquals("SHA256withRSA",              dto.getSignatureAlgorithm());
        Assertions.assertEquals("ML-DSA",                     dto.getAltSignatureAlgorithm());
        Assertions.assertEquals(certificate.getNotBefore(),   dto.getNotBefore());
        Assertions.assertEquals(certificate.getNotAfter(),    dto.getNotAfter());
        Assertions.assertEquals(CertificateState.ISSUED,      dto.getState());
        Assertions.assertEquals(CertificateType.X509,         dto.getCertificateType());
        Assertions.assertEquals(ComplianceStatus.OK,          dto.getComplianceStatus());
        // issuerCertificateUuid branch
        Assertions.assertEquals(issuerUuid.toString(),        dto.getIssuerCertificateUuid());
        // owner branch
        Assertions.assertEquals(owner.getOwnerUuid().toString(), dto.getOwnerUuid());
        Assertions.assertEquals("alice",                      dto.getOwner());
        // raProfile branch (no authorityInstanceReference → uuid and name only)
        SimplifiedRaProfileDto raDto = dto.getRaProfile();
        Assertions.assertNotNull(raDto);
        Assertions.assertEquals(raProfile.uuid.toString(),    raDto.getUuid());
        Assertions.assertEquals("test-ra",                    raDto.getName());
        Assertions.assertTrue(raDto.getEnabled());
        Assertions.assertNull(raDto.getAuthorityInstanceUuid());
        // no private key set
        Assertions.assertFalse(dto.isPrivateKeyAvailability());
    }

    // ──────────────────────────────────────────────────────────────────────────
    // toSimpleDto
    // ──────────────────────────────────────────────────────────────────────────

    @Test
    void toSimpleDto_mapsAllFields() {
        CertificateSimpleDto dto = CertificateDetailDtoMapper.toSimpleDto(certificate, CertificateRelationType.RENEWAL);

        Assertions.assertEquals(certificate.uuid,              dto.getUuid());
        Assertions.assertEquals(CertificateType.X509,         dto.getCertificateType());
        Assertions.assertEquals(CertificateState.ISSUED,      dto.getState());
        Assertions.assertEquals(CertificateRelationType.RENEWAL, dto.getRelationType());
        Assertions.assertEquals("test.example.com",           dto.getCommonName());
        Assertions.assertEquals("CN=test.example.com",        dto.getSubjectDn());
        Assertions.assertEquals("Example CA",                 dto.getIssuerCommonName());
        Assertions.assertEquals("CN=Example CA",              dto.getIssuerDn());
        Assertions.assertEquals("0123456789abcdef",           dto.getSerialNumber());
        Assertions.assertEquals("aa:bb:cc",                   dto.getFingerprint());
        Assertions.assertEquals("RSA",                        dto.getPublicKeyAlgorithm());
        Assertions.assertEquals("ML-DSA",                     dto.getAltPublicKeyAlgorithm());
        Assertions.assertEquals("SHA256withRSA",              dto.getSignatureAlgorithm());
        Assertions.assertEquals("ML-DSA",                     dto.getAltSignatureAlgorithm());
        Assertions.assertEquals(certificate.getNotBefore(),   dto.getNotBefore());
        Assertions.assertEquals(certificate.getNotAfter(),    dto.getNotAfter());
    }
}
