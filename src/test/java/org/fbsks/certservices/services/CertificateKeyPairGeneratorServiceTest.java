package org.fbsks.certservices.services;

import static org.junit.Assert.assertNotNull;

import java.security.KeyPair;

import org.fbsks.certservices.BaseTest;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * 
 * @author fabio.resner
 *
 */
public class CertificateKeyPairGeneratorServiceTest extends BaseTest {

	@Autowired
	private CertificateKeyPairGeneratorService keyGenerator;

	/*
	 * Lower key-size for faster test execution
	 */
	private static final int KEY_SIZE_128 = 128;
	
	@Test
	public void shouldGenerateDefaultKeyPair() {
		KeyPair keyPair = this.keyGenerator.generateKeyPair();
		assertNotNull(keyPair);
	}
	
	@Test
	public void shouldGenerateKeyPairWithCustomKeySize() {
		KeyPair keyPair = this.keyGenerator.generateKeyPair(KEY_SIZE_128);
		assertNotNull(keyPair);
	}
	
	@Test(expected=RuntimeException.class)
	public void shouldFailGeneratingKeyPairBecauseOfInvalidKeySize() {
		this.keyGenerator.generateKeyPair(0);
	}
}
