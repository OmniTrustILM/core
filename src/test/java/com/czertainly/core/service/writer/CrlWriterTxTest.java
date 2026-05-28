package com.czertainly.core.service.writer;

import com.czertainly.core.dao.entity.Crl;
import com.czertainly.core.dao.entity.CrlEntry;
import com.czertainly.core.dao.entity.CrlEntryId;
import com.czertainly.core.dao.repository.CrlEntryRepository;
import com.czertainly.core.dao.repository.CrlRepository;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrlWriterTxTest extends BaseSpringBootTest {

    @Autowired
    private CrlWriter crlWriter;

    @Autowired
    private CrlRepository crlRepository;

    @Autowired
    private CrlEntryRepository crlEntryRepository;

    @Test
    void writerBeanIsASpringProxy() {
        assertTrue(AopUtils.isAopProxy(crlWriter),
                "CrlWriter must be a Spring AOP proxy so @Transactional advice is applied");
    }

    @Test
    void insertCrlPersistsRow() {
        Crl crl = newCrl("CN=WriterTxIssuer", uniqueSerial(), UUID.randomUUID());
        crlWriter.insertCrl(crl);

        Crl reloaded = crlRepository.findByIssuerDnAndSerialNumber(crl.getIssuerDn(), crl.getSerialNumber())
                .orElseThrow();
        assertEquals(crl.getUuid(), reloaded.getUuid());
        assertNotNull(reloaded.getNextUpdate());
    }

    @Test
    void insertCrlSecondCallWithSameIssuerIsConflictResolved() {
        String serial = uniqueSerial();
        Crl first = newCrl("CN=WriterTxIssuerConflict", serial, UUID.randomUUID());
        crlWriter.insertCrl(first);

        Crl second = newCrl("CN=WriterTxIssuerConflict", serial, UUID.randomUUID());
        // ON CONFLICT (issuer_dn, serial_number) DO NOTHING — second insert is a no-op.
        crlWriter.insertCrl(second);

        Crl reloaded = crlRepository.findByIssuerDnAndSerialNumber(first.getIssuerDn(), first.getSerialNumber())
                .orElseThrow();
        assertEquals(first.getUuid(), reloaded.getUuid(),
                "first-writer-wins under ON CONFLICT DO NOTHING — second insert must not overwrite the row");
    }

    @Test
    void insertCrlEntryPersistsRow() {
        Crl crl = newCrl("CN=EntryWriterIssuer", uniqueSerial(), UUID.randomUUID());
        crlWriter.insertCrl(crl);

        String entrySerial = "ABCD1234";
        Date revocationDate = new Date();
        crlWriter.insertCrlEntry(crl.getUuid(), entrySerial, revocationDate, "UNSPECIFIED");

        CrlEntry reloaded = crlEntryRepository.findById(new CrlEntryId(crl.getUuid(), entrySerial)).orElseThrow();
        assertEquals("UNSPECIFIED", reloaded.getRevocationReason().name());
    }

    private Crl newCrl(String issuerDn, String serial, UUID uuid) {
        Crl crl = new Crl();
        crl.setUuid(uuid);
        crl.setIssuerDn(issuerDn);
        crl.setSerialNumber(serial);
        crl.setCrlIssuerDn(issuerDn);
        crl.setCrlNumber("1");
        crl.setNextUpdate(new Date(System.currentTimeMillis() + 86_400_000L));
        return crl;
    }

    private String uniqueSerial() {
        return Long.toHexString(System.nanoTime()) + Long.toHexString(System.identityHashCode(new Object()));
    }
}
