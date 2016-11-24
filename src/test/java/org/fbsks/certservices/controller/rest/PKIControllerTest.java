package org.fbsks.certservices.controller.rest;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;

/**
 * 
 * @author fabio.resner
 *
 */
public class PKIControllerTest extends BaseTest {

	@Autowired
	private PKIController pkiController;
	
	@Test
	public void shouldGenerateNewPKI() {
		pkiController.generateNewPKI("testPKI");
		List<PKI> pkiList = pkiController.listPKIs();
		
		assertEquals("testPKI", pkiList.get(0).getName());
	}
	
	@Test
	public void shouldGenerateP12() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
		pkiController.generateNewPKI("testPKI");
		ResponseEntity<byte[]> p12response = pkiController.newPKICertificate("testPKI", "testSubject", "1234");
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
		
		keyStore.load(new ByteArrayInputStream(Base64.decode(p12response.getBody())), "1234".toCharArray());
		assertEquals(1, keyStore.size());
	}
}
