package org.fbsks.certservices.services;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

/**
 * 
 * @author fabio.resner
 *
 */
@Service
public class CertificateKeyPairGeneratorService {

	private static final String KEYS_ALG = "RSA";
	
	private static final int DEFAULT_KEY_SIZE = 4096;

	public KeyPair generateKeyPair() {
		return generateKeyPair(DEFAULT_KEY_SIZE);
	}
	
	public KeyPair generateKeyPair(int keySize) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEYS_ALG, BouncyCastleProvider.PROVIDER_NAME);

			keyGen.initialize(keySize, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();

			return keyPair;

		} catch (Exception e) {
			throw new RuntimeException("Error generating keypair: " + e.getMessage());
		}
	}
}
