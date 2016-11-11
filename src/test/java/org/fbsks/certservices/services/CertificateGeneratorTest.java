package org.fbsks.certservices.services;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class CertificateGeneratorTest {
	
	private CertificateGenerator certificateGenerator;

	@Before
	public void setUp() throws OperatorCreationException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		this.certificateGenerator = new CertificateGenerator();
	}

	@Test
	public void generateSelfSignedCertificate() throws IOException {
		X509CertificateHolder certHolder = this.certificateGenerator.generateSelfSignedCertificate("CN=TestSubject");

		assertEquals(certHolder.getIssuer(), new X500Name("CN=TestSubject"));
	}
}
