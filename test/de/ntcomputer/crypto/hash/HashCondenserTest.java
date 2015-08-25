package de.ntcomputer.crypto.hash;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;
import java.util.Scanner;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import net.i2p.crypto.eddsa.Utils;

public class HashCondenserTest {
	
    @Rule
    public ExpectedException exception = ExpectedException.none();

    @Test
    public void testHash() throws Exception {
    	// load data
    	URL url = HashCondenserTest.class.getResource("randomdata.bin");
    	File file = new File(url.toURI());
    	long fileSize = file.length();
    	
    	// load expected condensed version
    	URL url2 = HashCondenserTest.class.getResource("randomdata.hc");
    	@SuppressWarnings("resource")
		String expectedHex = new Scanner( new File(url2.toURI()) ).next();
    	byte[] expectedBin = Utils.hexToBytes(expectedHex);
    	
    	// run hash condenser
    	HashCondenser cond = HashCondenser.getInstance(131);
    	try (InputStream is = new FileInputStream(file)) {
    		byte[] result = cond.compute(is, fileSize);
    		assertThat("HashCondenser failed to produce correct result", result, is(equalTo(expectedBin)));
    	}
    }

}
