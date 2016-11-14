package org.fbsks.certservices.model;

import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;

import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class CertificateAuthority extends AbstractPersistable<Long> {

	private static final long serialVersionUID = 2939716867481218950L;

	private String caName;

	@OneToOne
	private CAIdentityContainer identityContainer;

	@ManyToOne
	@JoinColumn
	private PKI pki;

	protected CertificateAuthority() {}

	public CertificateAuthority(String caName, CAIdentityContainer identityContainer) {
		this.identityContainer = identityContainer;
		this.caName = caName;
	}

	public String getCaName() {
		return caName;
	}

	public void setCaName(String caName) {
		this.caName = caName;
	}

	public PKI getPki() {
		return pki;
	}

	public void setPki(PKI pki) {
		this.pki = pki;
	}

	public CAIdentityContainer getIdentityContainer() {
		return identityContainer;
	}

	public void setIdentityContainer(CAIdentityContainer identityRepository) {
		this.identityContainer = identityRepository;
	}
}