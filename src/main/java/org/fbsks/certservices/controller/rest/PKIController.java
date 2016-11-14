package org.fbsks.certservices.controller.rest;

import java.util.List;

import org.fbsks.certservices.controller.rest.jsonview.PKISummary;
import org.fbsks.certservices.model.PKI;
import org.fbsks.certservices.services.PKIService;
import org.springframework.beans.factory.annotation.Autowired;
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
}
