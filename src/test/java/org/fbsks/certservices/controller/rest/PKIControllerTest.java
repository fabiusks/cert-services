package org.fbsks.certservices.controller.rest;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.BaseTest;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.utils.GeneralUtils;
import org.junit.Before;
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
	
	@Before
	public void setUp() {
		pkiController.generateNewPKI("testPKI");
	}
	
	@Test
	public void shouldGenerateNewPKI() {
		List<PKI> pkiList = pkiController.listPKIs();
		
		assertEquals("testPKI", pkiList.get(0).getName());
	}
	
	@Test
	public void shouldGenerateP12() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, NoSuchProviderException {
		ResponseEntity<byte[]> p12response = pkiController.newPKICertificate("testPKI", "testSubject", "1234");
		
		KeyStore keyStore = KeyStore.getInstance("PKCS12", BouncyCastleProvider.PROVIDER_NAME);
		
		keyStore.load(new ByteArrayInputStream(Base64.decode(p12response.getBody())), "1234".toCharArray());
		assertEquals(1, keyStore.size());
	}
	
	@Test
	public void shouldGetCRLs() throws CRLException, CertificateException {		
		List<PKI> pkiList = pkiController.listPKIs();
		String caName = pkiList.get(0).getCas().get(0).getName();
		ResponseEntity<byte[]> crls = pkiController.getCRLs(caName);
		
		X509CRL crl = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(new ByteArrayInputStream(Base64.decode(crls.getBody())));
		assertEquals(caName, GeneralUtils.getParsedCRLX500Principal(crl));
	}
	
	@Test
	public void shouldAccessAIA() throws CRLException, IOException, CMSException {
		ResponseEntity<byte[]> aia = pkiController.getAIA("testPKI");
		
		CMSSignedData p7b = new CMSSignedData(Base64.decode(aia.getBody()));
		
		@SuppressWarnings("unchecked")
		List<X509CertificateHolder> certificates = new ArrayList<X509CertificateHolder>(p7b.getCertificates().getMatches(null));
		
		List<PKI> pkiList = pkiController.listPKIs();
		String caName = pkiList.get(0).getCas().get(0).getName();
		
		assertEquals(1, certificates.size());
		assertEquals(caName, GeneralUtils.getParsedCertificateCommonName(certificates.get(0)));
	}
}
