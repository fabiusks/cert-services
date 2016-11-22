package org.fbsks.certservices.services;

import java.io.IOException;
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
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;
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

	private static final int DAY_IN_MILLI = 24 * 60 * 60 * 1000;
	private static final int YEAR_IN_MILLI = 365 * DAY_IN_MILLI;

	private static final String CN_FORMAT = "CN=";
	private static final String GENERIC_SUBJECT_INFO = ",OU=CertServices,C=City,L=Country,O=Organization,E=email@certservices.org";
	
	private static final String SERVER_BASE_REST_PKI_URL = "http://localhost:8080/rest/pki/";
	private static final String CRL_URL = "/crl";
	private static final String AIA_URL = "/cert";

	public CertificateService() {
		Security.addProvider(new BouncyCastleProvider());
	}

	public X509CertificateHolder generateCertificate(String subjectName, PublicKey subjectPublicKey, String issuerName, KeyPair issuerKeyPair) {
		try {			
			SubjectPublicKeyInfo subjectPubKeyInfo = generatePublicKeyInfo(subjectPublicKey);
			SubjectPublicKeyInfo issuerPubKeyInfo = generatePublicKeyInfo(issuerKeyPair.getPublic());
			
			X509v3CertificateBuilder v3CertGen = initializeCertificateBuilder(subjectPubKeyInfo, subjectName, issuerName);

			addCRLSitributionPoints(issuerName, v3CertGen);
			addKeyIdentifiers(subjectPubKeyInfo, issuerPubKeyInfo, v3CertGen);
			addAuthorityInformationAccess(issuerName, v3CertGen);

			ContentSigner sigGen = generateContentSignerBuilder(issuerKeyPair.getPrivate());
			X509CertificateHolder certHolder = v3CertGen.build(sigGen);

			return certHolder;

		} catch (Exception e) {
			LOGGER.error("Error while generating certificate: " + e.getMessage());
			throw new RuntimeException("Error while generating certificate", e);
		} 
	}
	
	public X509CertificateHolder generateSelfSignedCertificate(String subjectName, KeyPair keyPair) {
		return this.generateCertificate(subjectName, keyPair.getPublic(), subjectName, keyPair);
	}

	private ContentSigner generateContentSignerBuilder(PrivateKey issuerPrivateKey) throws OperatorCreationException, IOException {
		AsymmetricKeyParameter privateKeyParam = PrivateKeyFactory.createKey(issuerPrivateKey.getEncoded());

		AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(SIG_HASH_ALG);
		AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
		
		return new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(privateKeyParam);
	}

	private void addAuthorityInformationAccess(String issuerName, X509v3CertificateBuilder v3CertGen) throws CertIOException {
		AccessDescription caIssuers = new AccessDescription(AccessDescription.id_ad_caIssuers, new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(SERVER_BASE_REST_PKI_URL + issuerName + AIA_URL)));

		ASN1EncodableVector aia_ASN = new ASN1EncodableVector();
		aia_ASN.add(caIssuers);

		v3CertGen.addExtension(Extension.authorityInfoAccess, false, new DERSequence(aia_ASN));
	}

	private void addKeyIdentifiers(SubjectPublicKeyInfo subjectPubKeyInfo, SubjectPublicKeyInfo issuerPubKeyInfo, X509v3CertificateBuilder v3CertGen) throws OperatorCreationException, CertIOException {
		DigestCalculator digCalc = new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
		X509ExtensionUtils x509ExtensionUtils = new X509ExtensionUtils(digCalc);
	
		v3CertGen.addExtension(Extension.subjectKeyIdentifier, false, x509ExtensionUtils.createSubjectKeyIdentifier(subjectPubKeyInfo));
		v3CertGen.addExtension(Extension.authorityKeyIdentifier, false, x509ExtensionUtils.createAuthorityKeyIdentifier(issuerPubKeyInfo));
	}

	private void addCRLSitributionPoints(String issuerName, X509v3CertificateBuilder v3CertGen) throws CertIOException {
		DistributionPointName distributionPoint = new DistributionPointName(new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, SERVER_BASE_REST_PKI_URL + issuerName + CRL_URL)));

		DistributionPoint[] distPoints = new DistributionPoint[1];
		distPoints[0] = new DistributionPoint(distributionPoint, null, null);
		 
		v3CertGen.addExtension(Extension.cRLDistributionPoints, false, new CRLDistPoint(distPoints));
	}

	private X509v3CertificateBuilder initializeCertificateBuilder(SubjectPublicKeyInfo subjectPubKeyInfo, String subjectName, String issuerName) {
		X500Name subject = new X500Name(CN_FORMAT + subjectName + GENERIC_SUBJECT_INFO);
		X500Name issuer = new X500Name(CN_FORMAT + issuerName + GENERIC_SUBJECT_INFO);

		Date startDate = new Date(System.currentTimeMillis() - DAY_IN_MILLI);
		Date endDate = new Date(System.currentTimeMillis() + YEAR_IN_MILLI);
		
		return new X509v3CertificateBuilder(issuer, BigInteger.ONE, startDate, endDate, subject, subjectPubKeyInfo);
	}

	private SubjectPublicKeyInfo generatePublicKeyInfo(PublicKey subjectPublicKey) {
		byte[] encodedPublicKey = subjectPublicKey.getEncoded();
		return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(encodedPublicKey));
	}
}
