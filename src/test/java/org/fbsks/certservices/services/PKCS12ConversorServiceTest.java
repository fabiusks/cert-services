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

import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.IdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class PKCS12ConversorServiceTest extends BaseTest {

	@Autowired
	private PKCS12ConversorService p12Conversor;
	
	@Autowired
	private PKIService pkiService;
	
	private static final String TEST_PKI_NAME = "testPKI";
	private static final String TEST_CERTIFICATE_NAME = "testPKI";
	private static final String DEFAULT_KEYSTORE_PASSWORD = "123456";
	
	@Test
	public void shouldGenerateFinalUserPKCS12() throws KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, InvalidKeyException, CertificateException, NoSuchProviderException, SignatureException {
		PKI pki = this.pkiService.generatePKI(TEST_PKI_NAME);
		IdentityContainer identity = this.pkiService.generateIdentity(TEST_PKI_NAME, TEST_CERTIFICATE_NAME);
		
		KeyStore keyStore = this.p12Conversor.generatePKCS12(identity);
		String certificateAlias = keyStore.aliases().nextElement();
		Certificate certificate = keyStore.getCertificate(certificateAlias);
		
		assertTrue(certificate != null);
		assertTrue(keyStore.getKey(certificateAlias, DEFAULT_KEYSTORE_PASSWORD.toCharArray()) != null);

		certificate.verify(pki.getCas().get(0).getIdentityContainer().getPublicKey());
	}
}
