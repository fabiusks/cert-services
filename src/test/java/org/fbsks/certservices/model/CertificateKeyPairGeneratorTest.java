package org.fbsks.certservices.model;

import static org.junit.Assert.*;

import java.security.KeyPair;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

/**
 * 
 * @author fabio.resner
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest
public class CertificateKeyPairGeneratorTest {

	@Autowired
	private CertificateKeyPairGenerator keyGenerator;

	/*
	 * Lower key-size for faster test execution
	 */
	private static final int KEY_SIZE_1024 = 128;
	
	@Test
	public void shouldGenerateDefaultKeyPair() {
		KeyPair keyPair = this.keyGenerator.generateKeyPair();
		assertNotNull(keyPair);
	}
	
	@Test
	public void shouldGenerateKeyPairWithCustomKeySize() {
		KeyPair keyPair = this.keyGenerator.generateKeyPair(KEY_SIZE_1024);
		assertNotNull(keyPair);
	}
	
	@Test(expected=RuntimeException.class)
	public void shouldFailGeneratingKeyPairBecauseOfInvalidKeySize() {
		this.keyGenerator.generateKeyPair(0);
	}
}
