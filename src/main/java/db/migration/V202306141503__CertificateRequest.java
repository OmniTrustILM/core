package db.migration;

import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.core.dao.entity.CertificateRequestEntity;
import com.otilm.core.util.CertificateUtil;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

public class V202306141503__CertificateRequest extends BaseJavaMigration {

    private static final Logger logger = LoggerFactory.getLogger(V202306141503__CertificateRequest.class);

    private static final String INSERT_CERTIFICATE_REQUEST_SCRIPT =
            "Insert into certificate_request (uuid, common_name, i_author, i_cre, i_upd, subject_dn, public_key_algorithm, " +
                    "signature_algorithm, fingerprint, subject_alternative_names, key_usage, content, " +
                    "certificate_type, certificate_request_format, attributes, signature_attributes)" +
                    "values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)";

    private static final String UPDATE_CERTIFICATE_BY_CERTIFICATE_REQUEST =
            "UPDATE certificate SET certificate_request_uuid = %s WHERE uuid = %s";

    private static final List<String> SQL_FOR_FINAL_STEPS = List.of(
            "ALTER TABLE certificate DROP COLUMN csr_attributes;",
            "ALTER TABLE certificate DROP COLUMN signature_attributes;",
            "ALTER TABLE certificate DROP COLUMN csr;"
    );

    @Override
    public void migrate(final Context context) throws Exception {
        try (final Statement select = context.getConnection().createStatement()) {
            migrateCertificateToCertificateRequest(select);
        }
    }

    private void migrateCertificateToCertificateRequest(final Statement select) throws SQLException, CertificateException, NoSuchAlgorithmException {
        final List<String> sqlCommands = new ArrayList<>();
        final List<CertificateRequestEntity> certificateRequestEntities = new ArrayList<>();
        UUID certificateRequestUuid;

        try (final ResultSet certificates = select.executeQuery("SELECT * FROM certificate")) {
            while (certificates.next()) {
                final String csrContent = certificates.getString("csr");
                final String certificateUuid = certificates.getString("uuid");

                final CertificateRequestEntity certificateRequestEntity = findCsrByContent(certificateRequestEntities, csrContent);
                if (certificateRequestEntity == null) {
                    final String commonName = certificates.getString("common_name");
                    if (csrContent == null) {
                        logger.info("There is no CSR for certificate {}.", commonName);
                        continue;
                    }
                    final String author = certificates.getString("i_author");
                    final String created = certificates.getString("i_cre");
                    final String updated = certificates.getString("i_upd");
                    final String subjectDN = certificates.getString("subject_dn");
                    final String algorithm = certificates.getString("public_key_algorithm");
                    final String signatureAlgorithm = certificates.getString("signature_algorithm");
                    final String san = certificates.getString("subject_alternative_names");
                    final String keyUsage = certificates.getString("key_usage");
                    final String certificateType = certificates.getString("certificate_type");
                    final String csrAttrs = certificates.getString("csr_attributes");
                    final String signatureAttrs = certificates.getString("signature_attributes");

                    final byte[] csrDecoded = Base64.getDecoder().decode(csrContent);

                    certificateRequestUuid = UUID.randomUUID();

                    final String sqlCommand =
                            String.format(INSERT_CERTIFICATE_REQUEST_SCRIPT,
                                    formatStringValue(certificateRequestUuid.toString()),
                                    formatStringValue(commonName),
                                    formatStringValue(author),
                                    formatStringValue(created),
                                    formatStringValue(updated),
                                    formatStringValue(subjectDN),
                                    formatStringValue(algorithm),
                                    formatStringValue(signatureAlgorithm),
                                    formatStringValue(CertificateUtil.getThumbprint(csrDecoded)),
                                    formatStringValue(san),
                                    formatStringValue(keyUsage),
                                    formatStringValue(csrContent),
                                    formatStringValue(certificateType),
                                    formatStringValue(CertificateRequestFormat.PKCS10.name()),
                                    formatStringValue(csrAttrs),
                                    formatStringValue(signatureAttrs)
                            );

                    logger.info(sqlCommand);
                    sqlCommands.add(sqlCommand);

                    final CertificateRequestEntity certRequest = new CertificateRequestEntity();
                    certRequest.setUuid(certificateRequestUuid);
                    certRequest.setContent(csrContent);
                    certificateRequestEntities.add(certRequest);
                } else {
                    certificateRequestUuid = certificateRequestEntity.getUuid();
                }

                final String sqlUpdateCommand =
                        UPDATE_CERTIFICATE_BY_CERTIFICATE_REQUEST.formatted(
                                formatStringValue(certificateRequestUuid.toString()),
                                formatStringValue(certificateUuid));
                logger.info(sqlUpdateCommand);
                sqlCommands.add(sqlUpdateCommand);
            }
        }
        executeCommands(select, sqlCommands);
        executeCommands(select, SQL_FOR_FINAL_STEPS);
    }

    private CertificateRequestEntity findCsrByContent(final List<CertificateRequestEntity> certificateRequestEntities, final String csrContent) {
        Optional<CertificateRequestEntity> certificateRequestOptional = certificateRequestEntities.stream().filter(cr -> cr.getContent().equals(csrContent)).findFirst();
        return certificateRequestOptional.isPresent() ? certificateRequestOptional.get() : null;
    }

    private String formatStringValue(final String value) {
        return value != null ? "'%s'".formatted(value.replace("'", "''")) : "null";
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for (final String command : commands) {
            logger.info(command);
            select.execute(command);
        }
    }

}
