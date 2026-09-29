package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.core.dao.entity.CertificateImportEntry;
import com.otilm.core.dao.entity.CertificateImportEntryState;
import com.otilm.core.dao.repository.CertificateImportEntryRepository;
import com.otilm.core.model.certificate.CertificateImportRecord;
import com.otilm.core.service.writer.CertificateImportWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest
class CertificateImportWriterITest extends BaseSpringBootTest {

    @Autowired
    private CertificateImportWriter certificateImportWriter;
    @Autowired
    private CertificateImportEntryRepository certificateImportEntryRepository;

    @Test
    void open_recordsAnEntry() throws Exception {
        // given
        UUID requesterUuid = UUID.randomUUID();

        // when
        CertificateImportRecord opened = certificateImportWriter.open(requesterUuid, "import-a", "digest-a");

        // then
        assertThat(opened.digest()).isEqualTo("digest-a");
        assertThat(opened.state()).isEqualTo(CertificateImportEntryState.OPEN);
        assertThat(opened.certificateUuid()).isNull();
        assertThat(opened.keyUuid()).isNull();
        CertificateImportEntry recorded = certificateImportEntryRepository.findById(opened.uuid()).orElseThrow();
        assertThat(recorded.getRequesterUuid()).isEqualTo(requesterUuid);
        assertThat(recorded.getImportId()).isEqualTo("import-a");
        assertThat(recorded.getDigest()).isEqualTo("digest-a");
        assertThat(recorded.getState()).isEqualTo(CertificateImportEntryState.OPEN);
        assertThat(recorded.getCreatedAt()).isNotNull();
        assertThat(recorded.getUpdatedAt()).isNotNull();
    }

    @Test
    void open_returnsTheOpenRecordOfTheSameEntry() throws Exception {
        // given
        UUID requesterUuid = UUID.randomUUID();
        CertificateImportRecord first = certificateImportWriter.open(requesterUuid, "import-b", "digest-b");

        // when
        CertificateImportRecord second = certificateImportWriter.open(requesterUuid, "import-b", "digest-b");

        // then
        assertThat(second.uuid()).isEqualTo(first.uuid());
        assertThat(certificateImportEntryRepository.count()).isEqualTo(1);
    }

    @Test
    void open_refusesAnImportIdUsedForAnotherDigest() throws Exception {
        // given
        UUID requesterUuid = UUID.randomUUID();
        certificateImportWriter.open(requesterUuid, "import-c", "digest-c");

        // when
        // then
        assertThatThrownBy(() -> certificateImportWriter.open(requesterUuid, "import-c", "another-digest"))
                .isInstanceOf(AlreadyExistException.class);
        assertThat(certificateImportEntryRepository.count()).isEqualTo(1);
    }

    @Test
    void open_keepsImportIdsApartPerRequester() throws Exception {
        // given
        UUID firstRequester = UUID.randomUUID();
        UUID secondRequester = UUID.randomUUID();

        // when
        CertificateImportRecord first = certificateImportWriter.open(firstRequester, "shared-import-id", "digest-d");
        CertificateImportRecord second = certificateImportWriter.open(secondRequester, "shared-import-id", "digest-e");

        // then
        assertThat(second.uuid()).isNotEqualTo(first.uuid());
        assertThat(certificateImportEntryRepository.count()).isEqualTo(2);
    }

    @Test
    void complete_recordsWhatTheEntryProduced() throws Exception {
        // given
        UUID requesterUuid = UUID.randomUUID();
        CertificateImportRecord opened = certificateImportWriter.open(requesterUuid, "import-f", "digest-f");
        UUID certificateUuid = UUID.randomUUID();
        UUID keyUuid = UUID.randomUUID();

        // when
        certificateImportWriter.complete(opened.uuid(), certificateUuid, keyUuid);

        // then
        CertificateImportRecord completed = certificateImportWriter.find(requesterUuid, "import-f").orElseThrow();
        assertThat(completed.state()).isEqualTo(CertificateImportEntryState.COMPLETED);
        assertThat(completed.certificateUuid()).isEqualTo(certificateUuid);
        assertThat(completed.keyUuid()).isEqualTo(keyUuid);
    }

    @Test
    void find_readsNothingForAnUnknownImportId() {
        // given
        // when
        Optional<CertificateImportRecord> found = certificateImportWriter.find(UUID.randomUUID(), "unknown-import-id");

        // then
        assertThat(found).isEmpty();
    }
}
