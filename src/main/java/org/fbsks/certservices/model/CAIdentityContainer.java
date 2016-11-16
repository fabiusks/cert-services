package org.fbsks.certservices.model;

import java.security.PrivateKey;

import javax.persistence.Entity;
import javax.persistence.OneToOne;

import org.bouncycastle.cert.X509CertificateHolder;

@Entity
public class CAIdentityContainer extends IdentityContainer {

	private static final long serialVersionUID = 3657183436298977558L;

	@OneToOne
	private CertificateAuthority certificateAuthority;

	protected CAIdentityContainer() {};
	
	public CAIdentityContainer (X509CertificateHolder certificate, PrivateKey privateKey) {
		super(certificate, privateKey);
	}
	
	public CertificateAuthority getCertificateAuthority() {
		return certificateAuthority;
	}

	public void setCertificateAuthority(CertificateAuthority certificateAuthority) {
		this.certificateAuthority = certificateAuthority;
	}
}
