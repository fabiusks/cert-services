package org.fbsks.certservices.services;

import java.security.KeyPair;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.fbsks.certservices.model.CAIdentityContainer;
import org.fbsks.certservices.model.CertificateAuthority;
import org.fbsks.certservices.model.IdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.repository.CAIdentityContainerRepository;
import org.fbsks.certservices.repository.CertificateAuthorityRepository;
import org.fbsks.certservices.repository.PKIRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class PKIService {

	@Autowired
	private CertificateService certificateService;
	
	@Autowired
	private CertificateKeyPairGeneratorService keyPairGenerator;
	
	@Autowired
	private PKIRepository pkiRepository;
	
	@Autowired
	private CertificateAuthorityRepository caRepository;
	
	@Autowired
	private CAIdentityContainerRepository caIdentityContainerRepository;
	
	private static final String ROOT_CA = "ROOTCA";
	
	public PKI generatePKI(String pkiName) {
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		X509CertificateHolder rootCertificate = this.certificateService.generateSelfSignedCertificate(pkiName + ROOT_CA, keyPair);
		
		CAIdentityContainer identityContainer = new CAIdentityContainer(rootCertificate, keyPair.getPrivate());
		caIdentityContainerRepository.save(identityContainer);
		
		CertificateAuthority rootCa = new CertificateAuthority(pkiName + ROOT_CA, identityContainer);
		caRepository.save(rootCa);
		
		PKI pki = new PKI(pkiName, rootCa);
		rootCa.setPki(pki);
		
		pkiRepository.save(pki);
	
		return pki;
	}
	
	public List<PKI> listPKIs() {
		return pkiRepository.findAll();
	}

	public IdentityContainer generateIdentity(String pkiName, String subjectName) {	
		PKI retrievedPKI = pkiRepository.findOneByName(pkiName);
		
		if(retrievedPKI == null) {
			throw new RuntimeException("Unable to find PKI with name: " + pkiName);
		}
		
		CertificateAuthority rootCA = retrievedPKI.getCas().get(0);
		
		X509CertificateHolder rootCertificate = rootCA.getIdentityContainer().getCertificate();
		KeyPair userKeyPair = keyPairGenerator.generateKeyPair();
		KeyPair issuerKeyPair = new KeyPair(rootCA.getIdentityContainer().getPublicKey(), rootCA.getIdentityContainer().getPrivateKey());
		X509CertificateHolder finalUserCertificate = this.certificateService.generateCertificate(subjectName, userKeyPair.getPublic(), rootCA.getName(), issuerKeyPair);
		
		IdentityContainer identifyContainer = new IdentityContainer(rootCertificate, finalUserCertificate, userKeyPair.getPrivate());

		return identifyContainer;
	}

	public X509CertificateHolder getCertificateChain(String subjectName) {
		CertificateAuthority ca = this.caRepository.findOneByName(subjectName + ROOT_CA);
		
		if(ca == null) {
			throw new RuntimeException("Unable to find Certificate Authority with name: " + subjectName);
		}
		
		return ca.getIdentityContainer().getCertificate();
		
	}
}
