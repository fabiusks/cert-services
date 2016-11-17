package org.fbsks.certservices.repository;

import org.fbsks.certservices.model.CAIdentityContainer;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * 
 * @author fabio.resner
 *
 */
@Repository
public interface CAIdentityContainerRepository extends JpaRepository<CAIdentityContainer, Long>{

}
