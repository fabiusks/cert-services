package org.fbsks.certservices.model;

import java.security.KeyPair;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.services.CertificateService;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 
 * @author fabio.resner
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class CertificateAuthorityTest {

	@Autowired
	private CertificateKeyPairGenerator keyPairGenerator;
	
	@Autowired
	private CertificateService certificateService;
	
	@Test
	public void shouldGenerateCA() {
		this.keyPairGenerator = new CertificateKeyPairGenerator();
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder certificate = certificateService.generateCertificate("TestSubject", keyPair.getPublic(), "testIssuer", keyPair.getPrivate());
		
		new CertificateAuthority("New CA", certificate, keyPair.getPrivate());
	}

}




