package org.fbsks.certservices.controller.rest;

import java.io.IOException;
import java.util.List;

import org.bouncycastle.util.encoders.Base64;
import org.fbsks.certservices.controller.rest.jsonview.PKISummary;
import org.fbsks.certservices.model.IdentityContainer;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.services.PKIService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.fasterxml.jackson.annotation.JsonView;

@RestController
@RequestMapping("/rest/pki")
public class PKIController {

	@Autowired
	private PKIService pkiService;
	
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
	public ResponseEntity<byte[]> newPKICertificate(@RequestParam String pkiName, @RequestParam String subjectName) throws IOException {
		IdentityContainer userIdentity = this.pkiService.generateIdentity(pkiName, subjectName);
		
		//TODO Return the userIdentity (as PKCS#12)
		return ResponseEntity.ok()
				.header("content-disposition", "attachment; filename=" + userIdentity.getCertificate().getSubject() + ".cer")
				.body(Base64.encode(userIdentity.getCertificate().getEncoded()));
	}
}
