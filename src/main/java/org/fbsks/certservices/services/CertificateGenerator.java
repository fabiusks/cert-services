package org.fbsks.certservices.services;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class CertificateGenerator {

	public static final Logger LOGGER = LoggerFactory.getLogger(CertificateGenerator.class);

	private static final String SIG_HASH_ALG = "SHA256withRSA";
	
	private static final int YEAR_IN_MILLI = 365 * 24 * 60 * 60 * 1000;
	private static final int DAY_IN_MILLI = 24 * 60 * 60 * 1000;
	
	private static final String CN_FORMAT = "CN=";
	
	public CertificateGenerator() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	public X509CertificateHolder generateCertificate(String subjectName, String issuerName, KeyPair keyPair) {
		try {
			PrivateKey privateKey= keyPair.getPrivate();
			PublicKey publicKey = keyPair.getPublic();

			byte[] encoded = publicKey.getEncoded();
			SubjectPublicKeyInfo subPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encoded));

			X500Name subject = new X500Name(CN_FORMAT + subjectName);
			X500Name issuer = new X500Name(CN_FORMAT + subjectName);

			Date startDate = new Date(System.currentTimeMillis() - DAY_IN_MILLI);
			Date endDate = new Date(System.currentTimeMillis() + YEAR_IN_MILLI);

			X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuer, BigInteger.ONE, startDate, endDate, subject, subPubKeyInfo);

			AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(privateKey.getEncoded());

			AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_HASH_ALG);
			AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);

			ContentSigner sigGen = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyParam);

			X509CertificateHolder certHolder = v3CertGen.build(sigGen);

			return certHolder;

		} catch (Exception e) {
			LOGGER.error("Error while generating self signed certificate: " + e.getMessage());
			throw new RuntimeException("Error while generating self signed certificate", e);
		} 
	}

	public X509CertificateHolder generateSelfSignedCertificate(String subjectName, KeyPair keyPair) {
		return this.generateCertificate(subjectName, subjectName, keyPair);
	}
}
