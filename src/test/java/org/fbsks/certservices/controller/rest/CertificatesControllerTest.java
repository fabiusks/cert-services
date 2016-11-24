package org.fbsks.certservices.controller.rest;

import static org.junit.Assert.*;

import java.io.IOException;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.utils.GeneralUtils;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

/**
 * 
 * @author fabio.resner
 *
 */
public class CertificatesControllerTest extends BaseTest {
	
	@Autowired
	private CertificatesController certificatesController;
	
	@Test
	public void shouldGenerateSelfSignedCertificate() throws IOException {
		ResponseEntity<byte[]> selfSignedCertificateEntity = this.certificatesController.generateSelfSignedCerficate("testSubject");
		X509CertificateHolder selfSignedCertificate = new X509CertificateHolder(Base64.decode(selfSignedCertificateEntity.getBody()));
		
		assertEquals("testSubject", GeneralUtils.getParsedCertificateCommonName(selfSignedCertificate));
	}

}
