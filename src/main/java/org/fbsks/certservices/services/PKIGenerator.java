package org.fbsks.certservices.services;

import java.security.KeyPair;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.Repository.PKIRepository;
import org.fbsks.certservices.model.CertificateAuthority;
import org.fbsks.certservices.model.CertificateKeyPairGenerator;
import org.fbsks.certservices.model.PKI;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class PKIGenerator {

	@Autowired
	private CertificateGenerator certificateGenerator;
	
	@Autowired
	private CertificateKeyPairGenerator keyPairGenerator;
	
	@Autowired
	private PKIRepository pkiRepository;
	
	private static final String ROOT_CA = "ROOTCA";
	
	public PKI generatePKI(String pkiName) {
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder rootCertificate = this.certificateGenerator.generateSelfSignedCertificate(pkiName + ROOT_CA, keyPair);
		CertificateAuthority rootCa = new CertificateAuthority(pkiName + ROOT_CA, rootCertificate, keyPair.getPrivate());
		
		PKI pki = new PKI(pkiName, rootCa);
		
		pkiRepository.save(pki);
		pkiRepository.flush();
	
		return pki;
	}
}
