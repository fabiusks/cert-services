package org.fbsks.certservices.services;

import static org.junit.Assert.*;

import org.fbsks.certservices.Repository.PKIRepository;
import org.fbsks.certservices.model.PKI;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.transaction.annotation.Transactional;

/**
 * 
 * @author fabio.resner
 *
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@Transactional
public class PKIGeneratorTest {

	@Autowired
	private PKIService pkiGenerator;
	
	@Autowired
	private PKIRepository pkiRepository; 
	
	private static final String TEST_PKI_NAME = "TESTPKI";
	
	@Test
	public void shouldGeneratePKIOnlyWithRootCA() {
		this.pkiGenerator.generatePKI(TEST_PKI_NAME);
		
		PKI pki = pkiRepository.findOneByName(TEST_PKI_NAME);
		
		assertEquals(TEST_PKI_NAME, pki.getName());
		assertNotNull(pki);
		assertEquals(true, pki.getCas().size() > 0);
	}
}
