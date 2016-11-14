package org.fbsks.certservices.services;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.fbsks.certservices.model.CertificateKeyPairGenerator;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 
 * @author fabio.resner
 *
 */
@RunWith(SpringRunner.class)
public class CertificateServiceTest {
	
	private CertificateService certificateGenerator;
	
	private static final String SUBJECT_NAME = "TestSubject";
	private static final String FINAL_SUBJECT_NAME = "CN=TestSubject";

	@Before
	public void setUp() throws OperatorCreationException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		this.certificateGenerator = new CertificateService();
	}

	@Test
	public void shouldGenerateSelfSignedCertificate() throws IOException {
		CertificateKeyPairGenerator keyPairGenerator = new CertificateKeyPairGenerator();
		
		X509CertificateHolder certHolder = this.certificateGenerator.generateSelfSignedCertificate(SUBJECT_NAME, keyPairGenerator.generateKeyPair());

		assertEquals(certHolder.getIssuer(), new X500Name(FINAL_SUBJECT_NAME));
		assertEquals(certHolder.getSubject(), new X500Name(FINAL_SUBJECT_NAME));
		assertEquals(certHolder.isValidOn(new Date()), true);
		
		/*
		 * On a self signed certificate, issuer and subject names must be the same
		 */
		assertEquals(certHolder.getIssuer(), certHolder.getSubject());
	}
	
	@Test
	public void shouldFailGeneratingCertificateBecauseOfInvalidKeyPair() {
		
	}
}
