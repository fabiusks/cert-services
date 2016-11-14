package org.fbsks.certservices.model;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.OneToMany;

import org.springframework.data.jpa.domain.AbstractPersistable;

@Entity
public class PKI extends AbstractPersistable<Long> {

	private static final long serialVersionUID = -140537791349423216L;

	@OneToMany
	private List<CertificateAuthority> cas; 
	
	private String name;
	
	protected PKI() {}
	
	public PKI(String name, List<CertificateAuthority> cas) {
		this.name = name;
		this.cas = cas;
	}
	
	public PKI(String name, CertificateAuthority ca) {
		this.name = name;
		
		this.cas = new ArrayList<CertificateAuthority>();
		this.cas.add(ca);
	}

	public List<CertificateAuthority> getCas() {
		return cas;
	}

	public String getName() {
		return name;
	}
	
	public void setCas(List<CertificateAuthority> cas) {
		this.cas = cas;
	}

	public void setName(String name) {
		this.name = name;
	}
}
