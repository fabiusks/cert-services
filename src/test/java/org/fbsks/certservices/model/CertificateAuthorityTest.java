package org.fbsks.certservices.model;

import java.security.KeyPair;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.services.CertificateKeyPairGeneratorService;
import org.fbsks.certservices.services.CertificateService;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class CertificateAuthorityTest extends BaseTest {

	@Autowired
	private CertificateKeyPairGeneratorService keyPairGenerator;
	
	@Autowired
	private CertificateService certificateService;
	
	@Test
	public void shouldGenerateCA() {
		this.keyPairGenerator = new CertificateKeyPairGeneratorService();
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder certificate = certificateService.generateCertificate("TestSubject", keyPair.getPublic(), "testIssuer", keyPair);
		CAIdentityContainer identityContainer = new CAIdentityContainer(certificate, keyPair.getPrivate());
		
		new CertificateAuthority("New CA", identityContainer);
	}

}




