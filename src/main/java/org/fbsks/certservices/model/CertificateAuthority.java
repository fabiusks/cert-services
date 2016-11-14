package org.fbsks.certservices.model;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.Lob;
import javax.persistence.ManyToOne;

import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class CertificateAuthority extends AbstractPersistable<Long> {

	private static final long serialVersionUID = 2939716867481218950L;

	private String caName;

	@Lob
	private byte[] certificate;

	@Lob
	private byte[] privateKey;

	@ManyToOne
	@JoinColumn
	private PKI pki;

	private static final String DEFAULT_KEY_ALG = "RSA";

	protected CertificateAuthority() {}

	public CertificateAuthority(String caName, X509CertificateHolder certificate, PrivateKey privateKey) {
		try {
			this.certificate = certificate.getEncoded();
			this.privateKey = privateKey.getEncoded();
			this.caName = caName;

		} catch (Exception e) {
			throw new RuntimeException("Error while creating certificate authority: " + e.getMessage());
		}
	}

	public String getCaName() {
		return caName;
	}

	public void setCaName(String caName) {
		this.caName = caName;
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

	public PKI getPki() {
		return pki;
	}

	public void setPki(PKI pki) {
		this.pki = pki;
	}
}