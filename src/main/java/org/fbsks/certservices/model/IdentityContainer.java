package org.fbsks.certservices.model;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

import javax.persistence.Entity;
import javax.persistence.Lob;

import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.springframework.data.jpa.domain.AbstractPersistable;

/**
 * 
 * @author fabio.resner
 *
 */
@Entity
public class IdentityContainer extends AbstractPersistable<Long>{

	private static final long serialVersionUID = -8463185953157204525L;

	@Lob
	protected byte[] certificate;

	@Lob
	protected byte[] privateKey;
	
	protected static final String DEFAULT_KEY_ALG = "RSA";
	
	protected IdentityContainer() {}
	
	public IdentityContainer(X509CertificateHolder certificate, PrivateKey privateKey) {
		try {
			this.certificate = certificate.getEncoded();
			this.privateKey = privateKey.getEncoded();

		} catch (Exception e) {
			throw new RuntimeException("Error while creating certificate authority: " + e.getMessage());
		}
	}

	public X509CertificateHolder getCertificate() {
		try {
			return new X509CertificateHolder(certificate);

		} catch (IOException e) {
			throw new RuntimeException("Error getting certificate: " + e.getMessage(), e);
		}
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}

	public PrivateKey getPrivateKey() {
		try {
			KeyFactory keyFactory = KeyFactory.getInstance(DEFAULT_KEY_ALG);
			PrivateKey generatedPrivateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKey));

			return generatedPrivateKey;
		} catch (Exception e) {
			throw new RuntimeException("Error while obtaining the PrivateKey: " + e.getMessage(), e);

		}
	}

	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}
	
	public PublicKey getPublicKey() {
		try {
			SubjectPublicKeyInfo subjectPublicKeyInfo = getCertificate().getSubjectPublicKeyInfo();
			RSAKeyParameters rsa = (RSAKeyParameters) PublicKeyFactory.createKey(subjectPublicKeyInfo);
			
			RSAPublicKeySpec rsaSpec = new RSAPublicKeySpec(rsa.getModulus(), rsa.getExponent());
			
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PublicKey rsaPub = kf.generatePublic(rsaSpec);
			
			return rsaPub;
			
		} catch (Exception e) {
			throw new RuntimeException("Error while getting Public Key: " + e.getMessage(), e);
		}
	}
}