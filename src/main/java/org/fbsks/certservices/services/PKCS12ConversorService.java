package org.fbsks.certservices.services;

import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.fbsks.certservices.model.IdentityContainer;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */

@Service
public class PKCS12ConversorService {

	public KeyStore generatePKCS12(IdentityContainer identity) {
		try {
			Security.addProvider(new BouncyCastleProvider());
			
			KeyStore keystore = KeyStore.getInstance("PKCS12", "BC");
			keystore.load(null, null);
			
			String alias = identity.getCertificate().getSubject().toString();
			PrivateKey privateKey = identity.getPrivateKey();
			
			X509Certificate certificate = new JcaX509CertificateConverter().getCertificate(identity.getCertificate());
			Certificate convertedCertificate = CertificateFactory.getInstance("X.509", "BC").generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
			Certificate[] chain = {convertedCertificate};
			
			keystore.setKeyEntry(alias, privateKey, null, chain);
			
			return keystore;
			
		} catch (Exception e) {
			throw new RuntimeException("Error while generating PKCS12: " + e.getMessage(), e);
		}
	}
}
