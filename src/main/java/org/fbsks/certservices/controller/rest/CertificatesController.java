package org.fbsks.certservices.controller.rest;

import java.io.IOException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.services.CertificateGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

/**
 * 
 * @author fabio.resner
 *
 */
@RestController
@RequestMapping("/rest/cert")
public class CertificatesController {
	
	private static final Logger LOGGER = LoggerFactory.getLogger(CertificatesController.class);

	@Autowired
	private CertificateGenerator certGenerator;
	
	@RequestMapping(path="/new/self-signed", method=RequestMethod.POST)
	public ResponseEntity<byte[]> generateSelfSignedCerficate() throws IOException {
		LOGGER.info("Received new self-signed certificate request");
		
		X509CertificateHolder certificate = certGenerator.generateSelfSignedCertificate("CN=TestSubject");
		
		return ResponseEntity.ok()
				.header("content-disposition", "attachment; filename=" + certificate.getSubject() + ".cer")
				.body(Base64.encode(certificate.getEncoded()));
	}
}
