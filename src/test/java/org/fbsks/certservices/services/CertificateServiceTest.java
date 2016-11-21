package org.fbsks.certservices.services;

import static org.junit.Assert.assertEquals;

import java.io.FileOutputStream;
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
import org.fbsks.certservices.BaseTest;
import org.junit.Before;
import org.junit.Test;

/**
 * 
 * @author fabio.resner
 *
 */
public class CertificateServiceTest extends BaseTest {
	
	private CertificateService certificateGenerator;
	
	private static final String SUBJECT_NAME = "TestSubject";
	private static final String FINAL_SUBJECT_NAME = "CN=TestSubject,OU=CertServices,C=City,L=Country,O=Organization,E=email@certservices.org";
	
	private static final String ISSUER_NAME = "TestIssuer";
	private static final String FINAL_ISSUER_NAME = "CN=TestIssuer,OU=CertServices,C=City,L=Country,O=Organization,E=email@certservices.org";

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

		assertEquals(new X500Name(FINAL_SUBJECT_NAME), certHolder.getSubject());
		assertEquals(new X500Name(FINAL_SUBJECT_NAME), certHolder.getIssuer());
		assertEquals(certHolder.isValidOn(new Date()), true);
		
		/*
		 * On a self signed certificate, issuer and subject names must be the same
		 */
		assertEquals(certHolder.getIssuer(), certHolder.getSubject());
		
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
		certificate.verify(keyPair.getPublic());
	}
	
	@Test
	public void shouldGenerateCertificate() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException, IOException {
		CertificateKeyPairGeneratorService keyPairGenerator = new CertificateKeyPairGeneratorService();
		
		KeyPair issuerKeyPair = keyPairGenerator.generateKeyPair();
		KeyPair userKeyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder certHolder = this.certificateGenerator.generateCertificate(SUBJECT_NAME, userKeyPair.getPublic(), ISSUER_NAME, issuerKeyPair.getPrivate());

		assertEquals(new X500Name(FINAL_ISSUER_NAME), certHolder.getIssuer());
		assertEquals(new X500Name(FINAL_SUBJECT_NAME), certHolder.getSubject());
		assertEquals(true, certHolder.isValidOn(new Date()));
		
		X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
		certificate.verify(issuerKeyPair.getPublic());
		
		/*
		 * Saving for verification of the fields of the certificate. Should be done programatically in the future
		 */
		FileOutputStream fileOut = new FileOutputStream("target" + System.getProperty("file.separator") + "test.cer");
		fileOut.write(certHolder.getEncoded());
		fileOut.close();
	}
	
	@Test
	public void shouldFailGeneratingCertificateBecauseOfInvalidKeyPair() {
		//TODO
	}
}
