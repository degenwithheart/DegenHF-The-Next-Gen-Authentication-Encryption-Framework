package com.degenhf.eccauth;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Produces;

/**
 * CDI Producer for ECC Authentication Service
 */
@ApplicationScoped
public class EccAuthProducer {

    @Produces
    @ApplicationScoped
    public EccAuthService produceEccAuthService() throws Exception {
        return new EccAuthService();
    }
}