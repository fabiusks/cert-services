package org.fbsks.certservices.model;

import java.security.PrivateKey;

import javax.persistence.Entity;
import javax.persistence.ManyToOne;

import org.bouncycastle.cert.X509CertificateHolder;
import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class CertificateAuthority extends AbstractPersistable<Long> {

	private static final long serialVersionUID = 2939716867481218950L;
	
	private String caName;
	
	private byte[] certificate;
	private byte[] privateKey;
	
	@ManyToOne
	private PKI pki;
	
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

	public byte[] getCertificate() {
		return certificate;
	}

	public void setCertificate(byte[] certificate) {
		this.certificate = certificate;
	}

	public byte[] getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}
}