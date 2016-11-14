package org.fbsks.certservices.controller.rest;

import org.fbsks.certservices.services.PKIService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/pki")
public class PKIController {

	@Autowired
	private PKIService pkiGenerator;
	
	@RequestMapping(path = "/new", method = RequestMethod.POST)
	public void generateNewPKI(@RequestParam String pkiName) {
		pkiGenerator.generatePKI(pkiName);
	}
	
	@RequestMapping(path = "/list", method = RequestMethod.GET)
	public void listPKIs() {
		
	}
}
