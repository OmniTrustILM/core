package com.otilm.core.util;

import java.io.IOException;
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

public final class CrlUtil {

    private CrlUtil() {
    }

    /**
     * Returns the URLs that a cRLDistributionPoints or freshestCRL extension value names. A malformed value throws an
     * {@link IOException} naming {@code extensionName}, so callers treat it as unreadable revocation data; BouncyCastle
     * reports most malformed values with an unchecked exception whose type depends on what is wrong with them. That
     * exception is kept only as the cause, since the message reaches API clients in the validation result.
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
            throw new IOException("The %s extension is malformed".formatted(extensionName), e);
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
}
