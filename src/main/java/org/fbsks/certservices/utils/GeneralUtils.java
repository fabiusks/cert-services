package org.fbsks.certservices.utils;

import java.security.cert.X509CRL;

import org.bouncycastle.cert.X509CertificateHolder;

/**
 * 
 * @author fabio.resner
 *
 */
public class GeneralUtils {
	
	public static final String CN = "CN=";
	public static final String EMPTY_STRING = "";
	public static final String COMMA = ",";
	
	public static String getParsedCertificateCommonName(X509CertificateHolder certificate) {
		String caCN = certificate.getSubject().toString();
		caCN = caCN.substring(0, caCN.indexOf(COMMA));
		caCN = caCN.replace(CN, EMPTY_STRING);

		return caCN;
	}
	
	public static String getParsedCRLX500Principal(X509CRL crl) {
		String crlName = crl.getIssuerX500Principal().toString();
		crlName = crlName.replace(CN, EMPTY_STRING);
		
		return crlName;
	}
}
