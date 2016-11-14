package org.fbsks.certservices.model;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import org.springframework.stereotype.Component;

/**
 * 
 * @author fabio.resner
 *
 */
@Component
public class CertificateKeyPairGenerator {

	private static final String KEYS_ALG = "RSA";
	private static final String BC_PROV = "BC";
	
	private static final int DEFAULT_KEY_SIZE = 4096;

	public KeyPair generateKeyPair() {
		return generateKeyPair(DEFAULT_KEY_SIZE);
	}
	
	public KeyPair generateKeyPair(int keySize) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEYS_ALG, BC_PROV);

			keyGen.initialize(keySize, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();

			return keyPair;

		} catch (Exception e) {
			throw new RuntimeException("Error generating keypair: " + e.getMessage());
		}
	}
}
