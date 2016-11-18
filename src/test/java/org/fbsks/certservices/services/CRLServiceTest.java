package org.fbsks.certservices.services;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.security.cert.X509CRL;

import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class CRLServiceTest extends BaseTest {

	private static final String NONEXISTING_CA_NAME = "NO_WAY_THIS_CA_NAME_EXISTS";
	private static final String TEST_PKI_NAME = "testPKI";
	
	@Autowired
	private CRLService crlService;
	
	@Autowired
	private PKIService pkiService;
	
	@Test
	public void shouldGenerateCRL() {
		PKI pki = this.pkiService.generatePKI(TEST_PKI_NAME);
		X509CRL crl = this.crlService.generateCRL(pki.getCas().get(0).getName());
		
		assertNotNull(crl);
		assertEquals(pki.getCas().get(0).getIdentityContainer().getCertificate().getSubject().toString(), crl.getIssuerX500Principal().getName());
	}
	
	@Test(expected=RuntimeException.class)
	public void shouldFailGeneratingCRLForNonExistingCRL() {
		this.crlService.generateCRL(NONEXISTING_CA_NAME);
	}
}
