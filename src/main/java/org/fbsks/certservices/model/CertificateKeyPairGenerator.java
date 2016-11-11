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

	public KeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance(KEYS_ALG, BC_PROV);

			keyGen.initialize(4096, new SecureRandom());
			KeyPair keyPair = keyGen.generateKeyPair();

			return keyPair;

		} catch (Exception e) {
			throw new RuntimeException("Error generating keypair: " + e.getMessage());
		}
	}
}
