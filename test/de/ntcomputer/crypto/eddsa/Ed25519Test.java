package de.ntcomputer.crypto.eddsa;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

import java.io.File;
import java.math.BigInteger;
import java.net.URL;
import java.security.SecureRandom;
import java.security.SignatureException;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import de.ntcomputer.crypto.hash.HashCondenserTest;

public class Ed25519Test {
	
	@Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testKeyLifecycle() throws Exception {
    	SecureRandom random = new SecureRandom();
    	File privateKeyFile = new File("eddsa-junit-test-privatekey");
    	File publicKeyFile = new File("eddsa-junit-test-publickey");
    	
    	try {
    		Ed25519PrivateKey privateKey = Ed25519PrivateKey.generate();
    		Ed25519PublicKey publicKey = privateKey.derivePublicKey();
    		
    		URL testSignDataURL = HashCondenserTest.class.getResource("randomdata.bin");
        	File testSignDataFile = new File(testSignDataURL.toURI());
        	String signature = privateKey.sign(testSignDataFile, null);
        	
        	boolean verifyResult = publicKey.verify(testSignDataFile, signature, null);
    		assertThat("Ed25519 signature verification failure", verifyResult, is(true));
    		
    		char[] password = new BigInteger(130, random).toString(32).toCharArray();
    		privateKey.saveAsFile(privateKeyFile, password);
    		privateKey = Ed25519PrivateKey.loadFromFile(privateKeyFile, password);
    		
    		String signature2 = privateKey.sign(testSignDataFile, null);
    		assertThat("Ed25519 signature regeneration failure", signature2, is(equalTo(signature)));
    		
    		publicKey.saveAsFile(publicKeyFile);
    		publicKey = Ed25519PublicKey.loadFromFile(publicKeyFile);
    		
    		verifyResult = publicKey.verify(testSignDataFile, signature, null);
    		assertThat("Ed25519 signature reverification failure", verifyResult, is(true));
    		
    		exception.expect(SignatureException.class);
            exception.expectMessage("signature length is wrong");
    		publicKey.verify(testSignDataFile, "", null);
    		
    	} finally {
    		privateKeyFile.delete();
    		publicKeyFile.delete();
    	}
    }

}
