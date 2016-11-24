package org.fbsks.certservices.utils;

import static org.junit.Assert.assertEquals;

import java.security.cert.X509CRL;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.services.CRLService;
import org.fbsks.certservices.services.CertificateKeyPairGeneratorService;
import org.fbsks.certservices.services.CertificateService;
import org.fbsks.certservices.services.PKIService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class GeneralUtilsTest extends BaseTest {

	@Autowired
	private CertificateService certificateService;
	
	@Autowired
	private CRLService crlService;
	
	@Autowired
	private CertificateKeyPairGeneratorService keyGenService;
	
	@Autowired
	private PKIService pkiService;
	
	@Test
	public void shouldParseCertificateCommomName() {
		X509CertificateHolder certificate = certificateService.generateSelfSignedCertificate("Subject", keyGenService.generateKeyPair());
		String parsedSubject = GeneralUtils.getParsedCertificateCommonName(certificate);
		
		assertEquals("Subject", parsedSubject);
	}
	
	@Test
	public void shouldGetParsedCRLX500Principal() {
		PKI pki = pkiService.generatePKI("testPKI");
		X509CRL crl = crlService.generateCRL(pki.getCas().get(0).getName());
		
		String crlName = GeneralUtils.getParsedCRLX500Principal(crl);
		assertEquals("testPKIROOTCA", crlName);
	}
}
