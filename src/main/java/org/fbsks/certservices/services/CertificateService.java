package org.fbsks.certservices.services;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extension;
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
public class CertificateService {

	public static final Logger LOGGER = LoggerFactory.getLogger(CertificateService.class);

	private static final String SIG_HASH_ALG = "SHA256withRSA";

	private static final int YEAR_IN_MILLI = 365 * 24 * 60 * 60 * 1000;
	private static final int DAY_IN_MILLI = 24 * 60 * 60 * 1000;

	private static final String CN_FORMAT = "CN=";
	private static final String SERVER_BASE_REST_PKI_URL = "http://localhost:8080/rest/pki/";
	private static final String CRL_URL = "/crl";
	private static final String AIA_URL = "/cert";

	public CertificateService() {
		Security.addProvider(new BouncyCastleProvider());
	}

	//TODO PLEASE REFACTOR ME
	public X509CertificateHolder generateCertificate(String subjectName, PublicKey subjectPublicKey, String issuerName, PrivateKey issuerPrivateKey) {
		try {			
			byte[] encodedPublicKey = subjectPublicKey.getEncoded();
			SubjectPublicKeyInfo subjectPubKeyInfo = new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encodedPublicKey));

			X500Name subject = new X500Name(CN_FORMAT + subjectName);
			X500Name issuer = new X500Name(CN_FORMAT + issuerName);

			Date startDate = new Date(System.currentTimeMillis() - DAY_IN_MILLI);
			Date endDate = new Date(System.currentTimeMillis() + YEAR_IN_MILLI);

			X509v3CertificateBuilder v3CertGen = new X509v3CertificateBuilder(issuer, BigInteger.ONE, startDate, endDate, subject, subjectPubKeyInfo);

			GeneralName CRLGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(SERVER_BASE_REST_PKI_URL + issuerName + CRL_URL));
			GeneralNames CRLGeneralNames = new GeneralNames(CRLGeneralName);
			DistributionPointName distributionPointName = new DistributionPointName(CRLGeneralNames);

			v3CertGen.addExtension(X509Extension.cRLDistributionPoints, false, distributionPointName);

			//Authority Information Access
			AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(SERVER_BASE_REST_PKI_URL + issuerName + AIA_URL)));

			ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
			aia_ASN.add(caIssuers);

			v3CertGen.addExtension(X509Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));

			AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded());

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
		return this.generateCertificate(subjectName, keyPair.getPublic(), subjectName, keyPair.getPrivate());
	}
}
