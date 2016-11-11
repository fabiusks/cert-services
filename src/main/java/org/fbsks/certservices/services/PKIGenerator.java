package org.fbsks.certservices.services;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class PKIGenerator {

	@Autowired
	private CertificateGenerator certificateGenerator;
	
	public void generatePKI(String pkiName) {
		
	}
}
