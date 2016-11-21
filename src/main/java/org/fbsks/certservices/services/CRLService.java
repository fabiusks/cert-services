package org.fbsks.certservices.services;

import java.math.BigInteger;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.fbsks.certservices.model.CertificateAuthority;
import org.fbsks.certservices.repository.CertificateAuthorityRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class CRLService {

	@Autowired
	private CertificateAuthorityRepository caRepository;
	
	@SuppressWarnings("deprecation")
	public X509CRL generateCRL(String caName) {
		try {		
			CertificateAuthority ca = this.caRepository.findOneByName(caName);
			
			if(ca == null) {
				throw new RuntimeException("Error getting CRL for non existing CA: " + caName);
			}
			
			Date now = new Date();
			Date nextUpdate = new Date(now.getYear(), now.getMonth(), now.getDate(), now.getHours() + 3, now.getMinutes());

			X509V2CRLGenerator crlGenerator = new X509V2CRLGenerator();
			String caDN = getCADN(ca);
			
			crlGenerator.setIssuerDN(new X500Principal(caDN));
			crlGenerator.setThisUpdate(now);
			crlGenerator.setNextUpdate(nextUpdate);
			crlGenerator.setSignatureAlgorithm("SHA256withRSA");

			X509Certificate caCertificate = new JcaX509CertificateConverter().getCertificate(ca.getIdentityContainer().getCertificate());
			
			crlGenerator.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifierStructure(caCertificate));
			crlGenerator.addExtension(Extension.cRLNumber, false, new CRLNumber(BigInteger.ONE));
			
			X509CRL crl = crlGenerator.generateX509CRL(ca.getIdentityContainer().getPrivateKey(), BouncyCastleProvider.PROVIDER_NAME);
			
			return crl;
		} catch (Exception e) {
			throw new RuntimeException("Error while generating CRL: " + e.getMessage(), e);
		}
	}

	private String getCADN(CertificateAuthority ca) {
		String caCN = ca.getIdentityContainer().getCertificate().getSubject().toString();
		caCN = caCN.substring(0, caCN.indexOf(","));
		
		return caCN;
	}
}