package org.fbsks.certservices.repository;

import org.fbsks.certservices.model.PKI;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PKIRepository extends JpaRepository<PKI, Long> {
	
	PKI findOneByName(String pkiName);
}
