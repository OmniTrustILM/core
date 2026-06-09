package db.migration;

import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CzertainlyX500NameStyle;
import com.otilm.core.util.DatabaseMigration;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Migration script for the Public Key Changes
 */
public class V202311071500__IssuerAndSubjectDnMigration extends BaseJavaMigration {

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202311071500__IssuerAndSubjectDnMigration.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            createColumn(context);
            formatIssuerAndSubjectDn(context);
        }
    }

    private void formatIssuerAndSubjectDn(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT c.uuid, a.content FROM certificate c JOIN certificate_content a ON a.id = c.certificate_content_id")) {
                List<String> commands = new ArrayList<>();
                while (rows.next()) {
                    X509Certificate certificate = CertificateUtil.parseCertificate(rows.getString("content"));
                    byte[] subjectDnPrincipalEncoded = certificate.getSubjectX500Principal().getEncoded();
                    byte[] issuerDnPrincipalEncoded = certificate.getIssuerX500Principal().getEncoded();
                    commands.add(
                            "update certificate set issuer_dn = '" + X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, issuerDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                    commands.add(
                            "update certificate set subject_dn = '" + X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, subjectDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                    commands.add(
                            "update certificate set issuer_dn_normalized = '" + X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, issuerDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                    commands.add(
                            "update certificate set subject_dn_normalized = '" + X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, subjectDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                }
                executeCommands(select, commands);
            }

            try (ResultSet rows = select.executeQuery("SELECT c.uuid, c.content FROM certificate_request c")) {
                List<String> commands = new ArrayList<>();
                while (rows.next()) {
                    JcaPKCS10CertificationRequest jcaObject;
                    String content = rows.getString("content");
                    try {
                        jcaObject = CertificateRequestUtils.csrStringToJcaObject(content);
                    }
                    catch (IOException e) {
                        // BASE64 decode to also migrate certificate request content that was erroneously serialized as BASE64 encoded PEM
                        content = new String(Base64.getDecoder().decode(content));
                        jcaObject = CertificateRequestUtils.csrStringToJcaObject(content);
                    }

                    byte[] subjectDnPrincipalEncoded = jcaObject.getSubject().getEncoded();

                    commands.add(
                            "update certificate_request set subject_dn = '" + X500Name.getInstance(CzertainlyX500NameStyle.DEFAULT, subjectDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                    commands.add(
                            "update certificate_request set subject_dn_normalized = '" + X500Name.getInstance(CzertainlyX500NameStyle.NORMALIZED, subjectDnPrincipalEncoded).toString().replace("'", "''") + "' where uuid='" + rows.getString("uuid") + "'"
                    );
                }
                executeCommands(select, commands);
            }
        }
    }


    private void createColumn(Context context) throws Exception {
        String addIssuerDnNormalized = "ALTER TABLE certificate add column issuer_dn_normalized VARCHAR NULL DEFAULT NULL";
        String addSubjectDnNormalized = "ALTER TABLE certificate add column subject_dn_normalized VARCHAR NULL DEFAULT NULL";
        String addSubjectDnNormalizedCsr = "ALTER TABLE certificate_request add column subject_dn_normalized VARCHAR NULL DEFAULT NULL";
        try (Statement select = context.getConnection().createStatement()) {
            executeCommands(select, List.of(addIssuerDnNormalized, addSubjectDnNormalized, addSubjectDnNormalizedCsr));
        }
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for (String command : commands) {
            select.execute(command);
        }
    }
}