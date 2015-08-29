package de.ntcomputer.crypto.eddsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

import de.ntcomputer.crypto.hash.HashCondenser;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

public class Ed25519PublicKey {
	private final EdDSAPublicKey key;
	
	public static Ed25519PublicKey loadFromFile(File publicKeyFile) throws IOException, NoSuchAlgorithmException, InvalidKeyException {
		String key = new String(Files.readAllBytes(publicKeyFile.toPath()), StandardCharsets.UTF_8);
		return loadFromString(key);
	}
	
	public static Ed25519PublicKey loadFromString(String publicKeyString) throws InvalidKeyException, NoSuchAlgorithmException {
		if(publicKeyString.length() != (256+512)/8*2) throw new InvalidKeyException("the supplied key is not a valid public key"); // key + hash
		byte[] publicKey, publicKeyHashStored, publicKeyHash;
		try {
			publicKey = Utils.hexToBytes(publicKeyString.substring(0,256/8*2));
			publicKeyHashStored = Utils.hexToBytes(publicKeyString.substring(256/8*2));
		} catch(Exception e) {
			throw new InvalidKeyException("the supplied key is not a valid public key", e);
		}
		publicKeyHash = Ed25519PrivateKey.hash(publicKey);
		if(Utils.equal(publicKeyHash, publicKeyHashStored) != 1) throw new InvalidKeyException("the supplied public key is corrupted");
		return new Ed25519PublicKey(new EdDSAPublicKey(new EdDSAPublicKeySpec(publicKey, Ed25519PrivateKey.P_SPEC)));
	}
	
	Ed25519PublicKey(EdDSAPublicKey key) {
		this.key = key;
	}
	
	public void saveAsFile(File publicKeyFile) throws IOException, NoSuchAlgorithmException {
		String key = this.saveAsString();
		Files.write(publicKeyFile.toPath(), key.getBytes(StandardCharsets.UTF_8));
	}
	
	public String saveAsString() throws NoSuchAlgorithmException {
		byte[] publicKey = this.key.getAbyte();
		if(publicKey.length!=256/8) throw new RuntimeException(new InvalidKeyException("unexpected public key length"));
		byte[] publicKeyHash = Ed25519PrivateKey.hash(publicKey);
		return Utils.bytesToHex(publicKey) + Utils.bytesToHex(publicKeyHash);
	}
	
	private boolean verifyLow(byte[] data, String signature) throws SignatureException {
		byte[] signatureBytes;
		try {
			signatureBytes = Utils.hexToBytes(signature);
		} catch(Exception e) {
			throw new SignatureException("the supplied signature is not a valid signature", e);
		}
		EdDSAEngine engine = new EdDSAEngine();
		try {
			engine.initVerify(this.key);
			engine.update(data);
			return engine.verify(signatureBytes);
		} catch (InvalidKeyException e) {
			throw new RuntimeException(e);
		}
	}
	
	public boolean verify(byte[] data, String signature) throws NoSuchAlgorithmException, SignatureException {
		return this.verifyLow(HashCondenser.getInstance().compute(data), signature);
	}
	
	public boolean verify(String data, String signature) throws NoSuchAlgorithmException, SignatureException {
		return this.verify(data.getBytes(StandardCharsets.UTF_8), signature);
	}
	
	public boolean verify(InputStream source, long sourceSize, String signature) throws IllegalArgumentException, NoSuchAlgorithmException, IOException, SignatureException {
		return this.verifyLow(HashCondenser.getInstance().compute(source, sourceSize), signature);
	}
	
	public boolean verify(File source, String signature) throws IOException, IllegalArgumentException, NoSuchAlgorithmException, SignatureException {
		if(!source.isFile()) throw new FileNotFoundException(source.getAbsolutePath());
		long fileSize = source.length();
		try(InputStream is = new FileInputStream(source)) {
			return this.verify(is, fileSize, signature);
		}
	}
	
	public boolean verifyFromFile(File source) throws IOException, IllegalArgumentException, NoSuchAlgorithmException, SignatureException {
		return this.verifyFromFile(source, new File(source, ".sig"));
	}
	
	public boolean verifyFromFile(File source, File signatureFile) throws IOException, IllegalArgumentException, NoSuchAlgorithmException, SignatureException {
		String signature = new String(Files.readAllBytes(signatureFile.toPath()), StandardCharsets.UTF_8);
		return this.verify(source, signature);
	}

}
