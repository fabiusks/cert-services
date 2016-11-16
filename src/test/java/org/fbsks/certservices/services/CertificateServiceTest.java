package org.fbsks.certservices.services;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
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
	
	private static final String ISSUER_NAME = "TestIssuer";
	private static final String FINAL_ISSUER_NAME = "CN=TestIssuer";

	@Before
	public void setUp() throws OperatorCreationException, NoSuchAlgorithmException, IOException, NoSuchProviderException {
		Security.addProvider(new BouncyCastleProvider());
		this.certificateGenerator = new CertificateService();
	}

	@Test
	public void shouldGenerateSelfSignedCertificate() throws IOException, InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		CertificateKeyPairGeneratorService keyPairGenerator = new CertificateKeyPairGeneratorService();
		
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		X509CertificateHolder certHolder = this.certificateGenerator.generateSelfSignedCertificate(SUBJECT_NAME, keyPair);

		assertEquals(certHolder.getIssuer(), new X500Name(FINAL_SUBJECT_NAME));
		assertEquals(certHolder.getSubject(), new X500Name(FINAL_SUBJECT_NAME));
		assertEquals(certHolder.isValidOn(new Date()), true);
		
		/*
		 * On a self signed certificate, issuer and subject names must be the same
		 */
		assertEquals(certHolder.getIssuer(), certHolder.getSubject());
		
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
		certificate.verify(keyPair.getPublic());
	}
	
	@Test
	public void shouldGenerateCertificate() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		CertificateKeyPairGeneratorService keyPairGenerator = new CertificateKeyPairGeneratorService();
		
		KeyPair issuerKeyPair = keyPairGenerator.generateKeyPair();
		KeyPair userKeyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder certHolder = this.certificateGenerator.generateCertificate(SUBJECT_NAME, userKeyPair.getPublic(), ISSUER_NAME, issuerKeyPair.getPrivate());

		assertEquals(certHolder.getIssuer(), new X500Name(FINAL_ISSUER_NAME));
		assertEquals(certHolder.getSubject(), new X500Name(FINAL_SUBJECT_NAME));
		assertEquals(certHolder.isValidOn(new Date()), true);
		
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
		certificate.verify(issuerKeyPair.getPublic());
	}
	
	@Test
	public void shouldFailGeneratingCertificateBecauseOfInvalidKeyPair() {
		//TODO
	}
}
