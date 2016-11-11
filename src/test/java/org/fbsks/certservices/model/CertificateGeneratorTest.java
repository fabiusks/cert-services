package org.fbsks.certservices.model;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.junit.Before;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateGeneratorTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(CertificateGeneratorTest.class);
	
	private Date startDate;
	private Date endDate;
	private X500Name issuer;
	private X500Name subject;
	private BigInteger serial;
	
	private ContentSigner sigGen;
	private SubjectPublicKeyInfo subPubKeyInfo;
	
	private AsymmetricKeyParameter privateKeyParam;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	private X509v3CertificateBuilder v1CertGen;
	
	private static final String ISSUER_NAME = "CN=TestIssuer";
	private static final String SUBJECT_NAME = "CN=TestSubject";
	private static final String SIG_HASH_ALG = "SHA1withRSA";
	private static final String KEYS_ALG = "RSA";
	
	private static final String TEST_CERT_OUTPUT = "target" + System.getProperty("file.separator") + "generatedTestCert.cer";
	
	@Before
	public void setUp() throws OperatorCreationException, NoSuchAlgorithmException, IOException {
		this.startDate = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
		this.endDate = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000);
		
		this.issuer = new X500Name(ISSUER_NAME);
		this.subject = new X500Name(SUBJECT_NAME);
		this.serial = BigInteger.ONE;
		
		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_HASH_ALG);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEYS_ALG);
		keyGen.initialize(1024);
		
		KeyPair keyPair = keyGen.generateKeyPair();
		
		this.privateKey= keyPair.getPrivate();
		this.publicKey = keyPair.getPublic();
		
		byte[] encoded = this.publicKey.getEncoded();
		this.subPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));
		
		this.v1CertGen = new X509v3CertificateBuilder(issuer, serial, startDate, endDate, subject, subPubKeyInfo);
		
		this.privateKeyParam = PrivateKeyFactory.createKey(privateKey.getEncoded());
		this.sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyParam);
	}
	
	@Test
	public void generateSelfSignedCertificate() throws IOException {
		X509CertificateHolder certHolder = v1CertGen.build(sigGen);
		byte[] certificate = certHolder.getEncoded();
		
		File certFile = new File(TEST_CERT_OUTPUT);
		certFile.createNewFile();
		LOGGER.info(certFile.getAbsolutePath());
		
		FileOutputStream fos = new FileOutputStream(certFile);
		fos.write(certificate);
		fos.close();
		
		assertTrue(certHolder.getIssuer() != null);
	}
}
