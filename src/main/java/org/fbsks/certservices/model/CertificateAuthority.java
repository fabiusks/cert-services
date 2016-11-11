package org.fbsks.certservices.model;

import javax.persistence.Entity;
import javax.persistence.ManyToOne;

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
	
	public CertificateAuthority(String caName, byte[] certificate, byte[] privateKey) {
		this.certificate = certificate;
		this.privateKey = privateKey;
		this.caName = caName;
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