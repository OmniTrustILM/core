package com.otilm.core.service.scep.message;

public class ScepConstants {

    /**
     * SCEP attributes OIDs according to the RFC 8894
     * <a href="https://www.rfc-editor.org/rfc/rfc8894.html#section-3.2.1-7">SCEP attribute OIDs</a>
     */
    public static final String id_Verisign = "2.16.840.1.113733";
    public static final String id_pki = id_Verisign + ".1";
    public static final String id_attributes = id_pki + ".9";
    public static final String id_transactionId = id_attributes + ".7";
    public static final String id_messageType = id_attributes + ".2";
    public static final String id_pkiStatus = id_attributes + ".3";
    public static final String id_failInfo = id_attributes + ".4";
    public static final String id_senderNonce = id_attributes + ".5";
    public static final String id_recipientNonce = id_attributes + ".6";
    public static final String id_pkix = "1.3.6.1.5.5.7";
    public static final String id_scep = id_pkix + ".24";
    public static final String id_scep_failInfoText = id_scep + ".1";

}
