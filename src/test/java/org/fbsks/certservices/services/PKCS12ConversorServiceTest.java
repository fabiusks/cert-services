package org.fbsks.certservices.services;

import static org.junit.Assert.assertTrue;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import javax.transaction.Transactional;

import org.fbsks.certservices.model.IdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 
 * @author fabio.resner
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
public class PKCS12ConversorServiceTest {

	@Autowired
	private PKCS12ConversorService p12Conversor;
	
	@Autowired
	private PKIService pkiService;
	
	@Test
	public void shouldGeneratePKCS12() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException {
		PKI pki = this.pkiService.generatePKI("test");
		IdentityContainer identity = this.pkiService.generateIdentity("test", "testCertificate");
		
		KeyStore keyStore = this.p12Conversor.generatePKCS12(identity);
		String certificateAlias = keyStore.aliases().nextElement();
		Certificate certificate = keyStore.getCertificate(certificateAlias);
		
		assertTrue(certificate != null);
		assertTrue(keyStore.getKey(certificateAlias, "123456".toCharArray()) != null);

		certificate.verify(pki.getCas().get(0).getIdentityContainer().getPublicKey());
	}
}
