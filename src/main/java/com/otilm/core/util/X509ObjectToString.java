package com.otilm.core.util;

import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

public class X509ObjectToString {
	
	private static final Logger logger = LoggerFactory.getLogger(X509ObjectToString.class);
			
	private X509ObjectToString() {
		throw new IllegalStateException("Utility Class");
	}

	public static String toPem(X509Certificate certificate) {
	    StringWriter stringWriter = new StringWriter();
	    JcaPEMWriter pemWriter = new JcaPEMWriter(stringWriter);
	    try {
			pemWriter.writeObject(certificate);
			pemWriter.close();
		    return stringWriter.toString();
		} catch (IOException e) {
			logger.error("Error while getting certificate content");
			logger.error(e.getMessage());
			return "";
		}
	    
	  }
	}
