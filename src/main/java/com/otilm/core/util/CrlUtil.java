package com.otilm.core.util;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.URLConnection;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
@SuppressWarnings("java:S2696")
public class CrlUtil {
    private static int crlReadTimeout; // milliseconds
    private static int crlConnectTimeout; // milliseconds

    @Value("${validation.crl.read-timeout:1000}")
    public void setCrlReadTimeout(int timeout) {
        crlReadTimeout = timeout;
    }

    @Value("${validation.crl.connect-timeout:1000}")
    public void setCrlConnectTimeout(int timeout) {
        crlConnectTimeout = timeout;
    }

    private CrlUtil() {
    }

    /**
     * Returns the URLs that a cRLDistributionPoints or freshestCRL extension value names. A malformed value throws an
     * {@link IOException} naming {@code extensionName}, so callers treat it as unreadable revocation data; BouncyCastle
     * reports most malformed values with an unchecked exception whose type depends on what is wrong with them.
     */
    public static List<String> getCDPFromCertificate(byte[] extensionToDownloadFrom, String extensionName)
            throws IOException {

        if (extensionToDownloadFrom == null) {
            return new ArrayList<>();
        }
        DistributionPoint[] distributionPoints;
        try {
            distributionPoints = readDistributionPoints(extensionToDownloadFrom);
        } catch (IOException | RuntimeException e) {
            throw new IOException("The %s extension is malformed: %s".formatted(extensionName, e.getMessage()), e);
        }

        List<String> crlUrls = new ArrayList<>();
        for (DistributionPoint dp : distributionPoints) {
            DistributionPointName dpn = dp.getDistributionPoint();
            // Look for URIs in fullName
            if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                // Look for an URI
                for (GeneralName genName : genNames) {
                    if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                        String url = DERIA5String.getInstance(genName.getName()).getString();
                        crlUrls.add(url);
                    }
                }
            }
        }
        return crlUrls;
    }

    private static DistributionPoint[] readDistributionPoints(byte[] extensionValue) throws IOException {
        byte[] crlDistributionPoints = ASN1OctetString.getInstance(extensionValue).getOctets();
        try (ASN1InputStream crlDistributionPointsStream = new ASN1InputStream(crlDistributionPoints)) {
            CRLDistPoint crlDistPoint = CRLDistPoint.getInstance(crlDistributionPointsStream.readObject());
            if (crlDistPoint == null) {
                throw new IOException("its value is empty");
            }
            return crlDistPoint.getDistributionPoints();
        }
    }

    public static X509CRL getX509Crl(String crlUrl) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X509");

        // Handle ldap protocol
        if (crlUrl.startsWith("ldap")) {
            byte[] crl = LdapUtils.downloadFromLdap(crlUrl);
            if (crl == null) {
                throw new Exception("Crl not available in LDAP.");
            }
            return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl));
        }
        X509CRL x509Crl;
        URL url = URI.create(crlUrl).toURL();
        URLConnection connection = url.openConnection();
        connection.setConnectTimeout(crlConnectTimeout);
        connection.setReadTimeout(crlReadTimeout);

        try (DataInputStream inStream = new DataInputStream(connection.getInputStream())) {
            x509Crl = (X509CRL) cf.generateCRL(inStream);
        } catch (CRLException e) {
            throw new CertificateException("File " + e.getMessage() + " not found");
        }
        return x509Crl;
    }

}
