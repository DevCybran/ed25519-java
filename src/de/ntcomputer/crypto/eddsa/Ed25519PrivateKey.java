package de.ntcomputer.crypto.eddsa;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

import de.ntcomputer.crypto.hash.HashCondenser;
import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import net.i2p.crypto.eddsa.Utils;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;

/**
 * A wrapper class which makes it easy to generate and use Ed25519 private keys.
 * All methods are using java's {@link SecureRandom} PRNG, if a PRNG is needed.
 * All sign methods are using the {@link HashCondenser} for efficiency.
 * 
 * @author DevCybran
 *
 */
public class Ed25519PrivateKey implements Destroyable {
	static final EdDSAParameterSpec P_SPEC = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.CURVE_ED25519_SHA512);
	private static SecureRandom random = null;
	private final EdDSAPrivateKey key;
	private Ed25519PublicKey pubKey;
	
	private static SecureRandom random() {
		synchronized(Ed25519PrivateKey.class) {
			if(random==null) random = new SecureRandom();
			return random;
		}
	}
	
	private static SecretKey deriveKey(byte[] salt, char[] password) throws IllegalArgumentException, NoSuchAlgorithmException {
		if(password==null) throw new IllegalArgumentException("password must not be null");
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
		KeySpec ks = new PBEKeySpec(password, salt, 1000000, 256);
		try {
			SecretKey key = skf.generateSecret(ks);
			return new SecretKeySpec(key.getEncoded(), "AES");
		} catch (InvalidKeySpecException e) {
			throw new RuntimeException(e);
		}
	}
	
	static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(data);
	}
	
	/**
	 * Loads a private key from the specified file.
	 * 
	 * @param privateKeyFile the file to read the private key from
	 * @param password the password which was passed to {@link #saveAsFile(File, char[])} upon saving the file
	 * @return the read private key
	 * @throws IOException if an IO error occurs while reading the file
	 * @throws IllegalArgumentException if password is null
	 * @throws NoSuchAlgorithmException if either of the encryption algorithms is not present on this machine
	 * @throws NoSuchPaddingException if the PKCS5 padding is not present on this machine
	 * @throws InvalidKeyException if the key file has an invalid format
	 */
	public static Ed25519PrivateKey loadFromFile(File privateKeyFile, char[] password) throws IllegalArgumentException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		String key = new String(Files.readAllBytes(privateKeyFile.toPath()), StandardCharsets.UTF_8);
		return loadFromString(key, password);
	}
	
	/**
	 * Decodes a private key from the specified string.
	 * 
	 * @param privateKeyString A hexadecimal encoded representation of the key, generated by {@link #saveAsString(char[])}
	 * @param password the password which was passed to {@link #saveAsString(char[])} upon generating the privateKeyString
	 * @return the decoded private key
	 * @throws IllegalArgumentException if password is null
	 * @throws NoSuchAlgorithmException if either of the encryption algorithms is not present on this machine
	 * @throws NoSuchPaddingException if the PKCS5 padding is not present on this machine
	 * @throws InvalidKeyException if the passed privatKeyString has an invalid format
	 */
	public static Ed25519PrivateKey loadFromString(String privateKeyString, char[] password) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		if(privateKeyString.length() < (512+128+256+512)/8*2) throw new InvalidKeyException("the supplied key is not a valid private key"); // salt + iv + key + hash
		byte[] salt, iv, encryptedKey;
		try {
			salt = Utils.hexToBytes(privateKeyString.substring(0,512/8*2));
			iv = Utils.hexToBytes(privateKeyString.substring(512/8*2,(512+128)/8*2));
			encryptedKey = Utils.hexToBytes(privateKeyString.substring((512+128)/8*2));
		} catch(Exception e) {
			throw new InvalidKeyException("the supplied key is not a valid private key", e);
		}
		SecretKey key = deriveKey(salt, password);
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] encodedKey = cipher.doFinal(encryptedKey);
			if(encodedKey.length != (256+512)/8) throw new InvalidKeyException("the supplied key is not a valid private key");
			byte[] privateKeySeed = new byte[256/8];
			byte[] privateKeySeedHashStored = new byte[512/8];
			System.arraycopy(encodedKey, 0, privateKeySeed, 0, 256/8);
			System.arraycopy(encodedKey, 256/8, privateKeySeedHashStored, 0, 512/8);
			byte[] privateKeySeedHash = hash(privateKeySeed);
			if(Utils.equal(privateKeySeedHash, privateKeySeedHashStored) != 1) throw new InvalidKeyException("the supplied private key is corrupted or the password is wrong");
			return new Ed25519PrivateKey(new EdDSAPrivateKey(new EdDSAPrivateKeySpec(privateKeySeed, P_SPEC)), null);
		} catch (IllegalBlockSizeException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} catch (BadPaddingException e) {
			throw new InvalidKeyException("the supplied private key is corrupted or the password is wrong", e);
		} finally {
			try {
				key.destroy();
			} catch (DestroyFailedException e) {
			}
		}
	}
	
	/**
	 * Generates a new private key.
	 * {@link SecureRandom} is used as a source to seed this key.
	 *  
	 * 
	 * @return A new private key
	 */
	public static Ed25519PrivateKey generate() {
		KeyPairGenerator gen = new KeyPairGenerator();
		try {
			gen.initialize(P_SPEC, random());
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		}
		KeyPair pair = gen.generateKeyPair();
		return new Ed25519PrivateKey((EdDSAPrivateKey) pair.getPrivate(), new Ed25519PublicKey((EdDSAPublicKey) pair.getPublic()));
	}
	
	private Ed25519PrivateKey(EdDSAPrivateKey key, Ed25519PublicKey pubKey) {
		this.key = key;
		this.pubKey = pubKey;
	}
	
	/**
	 * Encrypts, encodes and saves this key to the specified file.
	 * 
	 * @see #saveAsString(char[])
	 * @param privateKeyFile the file to save the private key to
	 * @param password a password for encrypting the private key. The longer, the better.
	 * @throws IllegalArgumentException if password is null
	 * @throws IOException if an IO error occurs when writing the file
	 * @throws NoSuchAlgorithmException if either of the encryption algorithms is not present on this machine
	 * @throws NoSuchPaddingException if the PKCS5 padding is not present on this machine
	 */
	public void saveAsFile(File privateKeyFile, char[] password) throws IllegalArgumentException, IOException, NoSuchAlgorithmException, NoSuchPaddingException {
		String key = this.saveAsString(password);
		Files.write(privateKeyFile.toPath(), key.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Encodes this key as a hexadecimal String.
	 * A password is used to encrypt this key. The password and a generated 512-bit long salt are fed to 1 million iterations of PBKDF2 with SHA-512 to generate a secret key.
	 * The secret key is used to encrypt the private key using AES-256-CBC-PKCS5.
	 * 
	 * @param password a password for encrypting the private key. The longer, the better.
	 * @return a hexadecimal encoded and encrypted representation of this private key
	 * @throws IllegalArgumentException if password is null
	 * @throws NoSuchAlgorithmException if either of the encryption algorithms is not present on this machine
	 * @throws NoSuchPaddingException if the PKCS5 padding is not present on this machine
	 */
	public String saveAsString(char[] password) throws IllegalArgumentException, NoSuchAlgorithmException, NoSuchPaddingException {
		byte[] salt = new byte[512/8];
		random().nextBytes(salt);
		byte[] iv = new byte[128/8];
		random().nextBytes(iv);
		byte[] privateKeySeed = this.key.getSeed();
		if(privateKeySeed.length!=256/8) throw new RuntimeException(new InvalidKeyException("unexpected private key length"));
		byte[] privateKeySeedHash = hash(privateKeySeed);
		byte[] encodedKey = new byte[256/8 + 512/8];
		System.arraycopy(privateKeySeed, 0, encodedKey, 0, 256/8);
		System.arraycopy(privateKeySeedHash, 0, encodedKey, 256/8, 512/8);
		SecretKey key = deriveKey(salt, password);
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
			byte[] encryptedKey = cipher.doFinal(encodedKey);
			return Utils.bytesToHex(salt) + Utils.bytesToHex(iv) + Utils.bytesToHex(encryptedKey);
		} catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} finally {
			try {
				key.destroy();
			} catch (DestroyFailedException e) {
			}
		}
	}
	
	/**
	 * Creates (if necessary) and returns the public key for this private key.
	 * 
	 * @return the public key for this private key
	 */
	public Ed25519PublicKey derivePublicKey() {
		if(this.pubKey==null) {
			this.pubKey = new Ed25519PublicKey(new EdDSAPublicKey(new EdDSAPublicKeySpec(this.key.getA(), this.key.getParams())));
		}
		return this.pubKey;
	}
	
	private String signLow(byte[] data) {
		EdDSAEngine engine = new EdDSAEngine();
		try {
			engine.initSign(this.key);
			engine.update(data);
			byte[] signature = engine.sign();
			String signatureHex = Utils.bytesToHex(signature);
			return signatureHex;
		} catch (InvalidKeyException | SignatureException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Signs the given byte array.
	 * {@link HashCondenser#compute(byte[])} with default settings is preprocessing the array before signing it.
	 * 
	 * @param data
	 * @return a hexadecimal representation of the signature
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 */
	public String sign(byte[] data) throws NoSuchAlgorithmException {
		return signLow(HashCondenser.getInstance().compute(data));
	}
	
	/**
	 * Signs the given String by converting it to bytes using the UTF-8 charset.
	 * 
	 * @see #sign(byte[])
	 * @param data
	 * @return a hexadecimal representation of the signature
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 */
	public String sign(String data) throws NoSuchAlgorithmException {
		return this.sign(data.getBytes(StandardCharsets.UTF_8));
	}
	
	/**
	 * Signs all data which can be read from the given InputStream.
	 * {@link HashCondenser#compute(byte[])} with default settings is preprocessing the stream before signing it, which will allow signing huge files.
	 * 
	 * @param source the data source
	 * @param sourceSize the exact size of all data which will pass through the InputStream
	 * @return a hexadecimal representation of the signature
	 * @throws IllegalArgumentException if sourceSize is not the correct size
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 * @throws IOException if an IO error occurs while reading the stream
	 */
	public String sign(InputStream source, long sourceSize) throws IllegalArgumentException, NoSuchAlgorithmException, IOException {
		return signLow(HashCondenser.getInstance().compute(source, sourceSize));
	}
	
	/**
	 * Signs the content of the given file.
	 * 
	 * @see #sign(InputStream, long)
	 * @param source
	 * @return a hexadecimal representation of the signature
	 * @throws IOException if an IO error occurs while reading the file
	 * @throws IllegalArgumentException if the file's size changes during computation
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 */
	public String sign(File source) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
		if(!source.isFile()) throw new FileNotFoundException(source.getAbsolutePath());
		long fileSize = source.length();
		try(InputStream is = new FileInputStream(source)) {
			return this.sign(is, fileSize);
		}
	}
	
	/**
	 * Signs the content of the given file and writes the signature to a file of the same name which has a ".sig" extension appended
	 * Example: If you sign "MyFile.dat", the signature will be written to "MyFile.dat.sig"
	 * 
	 * @see #signToFile(File, File)
	 * @param source
	 * @throws IOException if an IO error occurs while reading or writing a file
	 * @throws IllegalArgumentException if the file's size changes during computation
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 */
	public void signToFile(File source) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
		this.signToFile(source, new File(source, ".sig"));
	}
	
	/**
	 * Signs the content of the given source file and writes the signature to the given signature file. 
	 * 
	 * @see #sign(File)
	 * @param source
	 * @param signatureFile the file to write the signature to
	 * @throws IOException if an IO error occurs while reading or writing a file
	 * @throws IllegalArgumentException if the file's size changes during computation
	 * @throws NoSuchAlgorithmException if the hash algorithm is not present on this machine
	 */
	public void signToFile(File source, File signatureFile) throws IOException, IllegalArgumentException, NoSuchAlgorithmException {
		String signature = this.sign(source);
		Files.write(signatureFile.toPath(), signature.getBytes(StandardCharsets.UTF_8));
	}

	@Override
	public void destroy() throws DestroyFailedException {
		this.key.destroy();
	}

	@Override
	public boolean isDestroyed() {
		return this.key.isDestroyed();
	}

}
