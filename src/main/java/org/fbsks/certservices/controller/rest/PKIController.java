package org.fbsks.certservices.controller.rest;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.controller.rest.jsonview.PKISummary;
import org.fbsks.certservices.model.IdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.services.PKCS12ConversorService;
import org.fbsks.certservices.services.PKIService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;

/**
 * 
 * @author fabio.resner
 *
 */
@RestController
@RequestMapping("/rest/pki")
public class PKIController {

	@Autowired
	private PKIService pkiService;
	
	@Autowired
	private PKCS12ConversorService p12Conversor;
	
	private static final String DEFAULT_PASSWORD = "123456";
	private static final String P12_EXTENSTION = ".p12";
	
	private static final String CONTENT_DISPOSITION_HEADER = "content-disposition";
	private static final String CONTENT_DISPOSITION_ARGS = "attachment; filename=";
	
	@RequestMapping(path = "/new", method = RequestMethod.POST)
	public void generateNewPKI(@RequestParam String pkiName) {
		pkiService.generatePKI(pkiName);
	}
	
	@JsonView(PKISummary.class)
	@RequestMapping(path = "/list", method = RequestMethod.GET)
	public List<PKI> listPKIs() {
		return pkiService.listPKIs();
	}
	
	//TODO Review exception thrown at this point
	//TODO Response Entity returning could be revised (could be done better)
	@RequestMapping(path="/cert/new", method = RequestMethod.POST)
	public ResponseEntity<byte[]> newPKICertificate(@RequestParam String pkiName, @RequestParam String subjectName) throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
		IdentityContainer userIdentity = this.pkiService.generateIdentity(pkiName, subjectName);
		KeyStore userPKCS12 = p12Conversor.generatePKCS12(userIdentity);
		
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		userPKCS12.store(output, DEFAULT_PASSWORD.toCharArray());
		
		return ResponseEntity.ok()
				.header(CONTENT_DISPOSITION_HEADER, CONTENT_DISPOSITION_ARGS + userIdentity.getCertificate().getSubject().toString().replaceFirst("CN=",  "") + P12_EXTENSTION)
				.body(Base64.encode(output.toByteArray()));
	}
}
