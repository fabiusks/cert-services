package org.fbsks.certservices.controller.rest;

import org.fbsks.certservices.services.PKIGenerator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/rest/pki")
public class PKIController {

	@Autowired
	private PKIGenerator pkiGenerator;
	
	@RequestMapping("/new")
	public void generateNewPKI(@RequestParam String pkiName) {
		
	}
}
