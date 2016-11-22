package org.fbsks.certservices.services;

import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class P7BService {

	public CMSSignedData generateP7B(X509CertificateHolder caCertificate, PrivateKey caPrivateKey) {
		try {
			List<X509CertificateHolder> certChain = new ArrayList<X509CertificateHolder>();
			certChain.add(caCertificate);

			Store certs = new JcaCertStore(certChain);

			CMSSignedDataGenerator cmsSignedDataGenerator = new CMSSignedDataGenerator();
			ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider(BouncyCastleProvider.PROVIDER_NAME).build(caPrivateKey);

			cmsSignedDataGenerator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(
					new JcaDigestCalculatorProviderBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME).build())
			.build(sha1Signer, caCertificate));
			cmsSignedDataGenerator.addCertificates(certs);

			CMSTypedData chainMessage = new CMSProcessableByteArray("chain".getBytes());
			CMSSignedData sigData = cmsSignedDataGenerator.generate(chainMessage, false);

			return sigData;
			
		} catch(Exception e) {
			throw new RuntimeException("Error while generating certificate chain: " + e.getMessage(), e);
		}
	}
}
