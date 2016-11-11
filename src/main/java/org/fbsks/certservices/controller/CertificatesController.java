package org.fbsks.certservices.controller;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.services.CertificateGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/cert")
public class CertificatesController {

	@Autowired
	private CertificateGenerator certGenerator;
	
	@RequestMapping(path="/new", method=RequestMethod.POST)
	public X509CertificateHolder generateCerficate() {
		return certGenerator.generateCertificate("CN=TestSubject", "CN=TestIssuer");
	}
	
	@RequestMapping(path="/new/self-signed", method=RequestMethod.POST)
	public X509CertificateHolder generateSelfSignedCerficate() {
		return certGenerator.generateSelfSignedCertificate("CN=TestSubject");
	}
}
