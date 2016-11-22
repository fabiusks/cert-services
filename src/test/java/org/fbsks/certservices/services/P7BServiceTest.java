package org.fbsks.certservices.services;

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.CAIdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class P7BServiceTest extends BaseTest {

	@Autowired
	private P7BService p7bService;
	
	@Autowired
	private PKIService pkiService;
	
	@Test
	public void shouldGenerateCertificateChain() {
		PKI pki = this.pkiService.generatePKI("testePKI");
		
		CAIdentityContainer caIdentityContainer = pki.getCas().get(0).getIdentityContainer();
		CMSSignedData certChainSignedData = this.p7bService.generateP7B(caIdentityContainer.getCertificate(), caIdentityContainer.getPrivateKey());
	
		@SuppressWarnings("unchecked")
		List<X509CertificateHolder> certChain = new ArrayList<X509CertificateHolder>(certChainSignedData.getCertificates().getMatches(null));
		
		assertEquals(pki.getCas().get(0).getIdentityContainer().getCertificate(), certChain.get(0));
	}
}
