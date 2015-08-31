package de.ntcomputer.crypto.hash;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import net.i2p.crypto.eddsa.Utils;

/**
 * A class which packs any byte input stream or array into a fixed-size output byte array using a {@link MessageDigest}.
 * This is useful when there is a need to sign or verify large files with a signature scheme that requires caching the input data (such as Ed25519).
 * The default {@link MessageDigest} is SHA-512, the default output size is 512 KiB.
 * 
 * @author DevCybran
 *
 */
public class HashCondenser {
	public static final int DEFAULT_OUTPUT_SIZE = 512*1024;
	private static final int LONG_SIZE = Long.SIZE/8;
	private final MessageDigest digest;
	private final MessageDigest segmentDigest;
	private final int outputSize;
	private final int digestLength;
	private final int hashCount;
	
	/**
	 * Returns a new instance using the given parameters.
	 * 
	 * @param md a MessageDigest. Must support {@link MessageDigest#getDigestLength()}.
	 * @param outputSize the size (in bytes) any input should be condensed to. Has to be greater than at least one digest length + 8.
	 * @return
	 * @throws IllegalArgumentException when the parameter conditions are not met
	 * @throws CloneNotSupportedException if the MessageDigest can't be cloned
	 */
	public static HashCondenser getInstance(MessageDigest md, int outputSize) throws IllegalArgumentException, CloneNotSupportedException {
		MessageDigest md1 = (MessageDigest) md.clone();
		MessageDigest md2 = (MessageDigest) md.clone();
		md1.reset();
		md2.reset();
		return new HashCondenser(md1, md2, outputSize);
	}
	
	/**
	 * Returns a new instance using the given output size and the SHA-512 digest.
	 * 
	 * @param outputSize the size (in bytes) any input should be condensed to. Has to be at least 72.
	 * @return
	 * @throws IllegalArgumentException when outputSize is invalid
	 * @throws NoSuchAlgorithmException when SHA-512 is not present on this machine
	 */
	public static HashCondenser getInstance(int outputSize) throws IllegalArgumentException, NoSuchAlgorithmException {
		return new HashCondenser(MessageDigest.getInstance("SHA-512"), MessageDigest.getInstance("SHA-512"), outputSize);
	}
	
	/**
	 * Returns a new instance using the given MessageDigest and the default output size (512 KiB).
	 * 
	 * @param md a MessageDigest. Must support {@link MessageDigest#getDigestLength()}.
	 * @return
	 * @throws IllegalArgumentException when the parameter conditions are not met
	 * @throws CloneNotSupportedException if the MessageDigest can't be cloned
	 */
	public static HashCondenser getInstance(MessageDigest md) throws IllegalArgumentException, CloneNotSupportedException{
		MessageDigest md1 = (MessageDigest) md.clone();
		MessageDigest md2 = (MessageDigest) md.clone();
		md1.reset();
		md2.reset();
		return new HashCondenser(md1, md2, DEFAULT_OUTPUT_SIZE);
	}
	
	/**
	 * Returns a new instance using the default parameters (512 KiB SHA-512).
	 * 
	 * @return
	 * @throws NoSuchAlgorithmException when SHA-512 is not present on this machine
	 */
	public static HashCondenser getInstance() throws NoSuchAlgorithmException {
		return new HashCondenser(MessageDigest.getInstance("SHA-512"), MessageDigest.getInstance("SHA-512"), DEFAULT_OUTPUT_SIZE);
	}
	
	private HashCondenser(MessageDigest md, MessageDigest md2, int outputSize) {
		this.digest = md;
		this.segmentDigest = md2;
		this.outputSize = outputSize;
		this.digestLength = md.getDigestLength();
		if(digestLength==0) throw new IllegalArgumentException("could not determine message digest length (returned 0)");
		if(this.outputSize < LONG_SIZE + this.digestLength*2) throw new IllegalArgumentException("output size is less than message digest length * 2 + overhead for one long value");
		this.hashCount = (this.outputSize - LONG_SIZE - digestLength) / digestLength;
	}
	
	/**
	 * Computes a condensed version of the input (data).
	 * 
	 * @see #compute(InputStream, long)
	 * @param data
	 * @return the condensed version of the input
	 */
	public byte[] compute(byte[] data) {
		try {
			return this.compute(new ByteArrayInputStream(data), data.length);
		} catch (IOException e) {
			// IOException should never happen for cached byte stream
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Computes a condensed version of the input (source).
	 * If sourceSize and a specific overhead is not greater than this object's outputSize, then a 0-padded copy of the source will be returned.
	 * Otherwise, a 0-padded concatenation of hashes for segments of the source will be returned.
	 * Every result contains the original sourceSize and a operation mode indicator.
	 * 
	 * @param source
	 * @param sourceSize the exact number of bytes which can be read from source 
	 * @return the condensed version of the input
	 * @throws IOException when source throws an IOException
	 * @throws IllegalArgumentException if sourceSize happens not to be the same as source's size
	 */
	public byte[] compute(InputStream source, long sourceSize) throws IOException, IllegalArgumentException {		
		// create result buffer
		byte[] result = new byte[this.outputSize];
		Arrays.fill(result, (byte) 0x00);
		
		this.digest.reset();
		
		if(sourceSize <= this.outputSize-LONG_SIZE-digestLength) {
			// copy source directly if short enough
			
			// add file size + negative sign as direct mode indicator
			ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).putLong(-sourceSize);
			
			int destOffset = LONG_SIZE+digestLength;
			int readSourceSize = 0;
			int readLength;
			while((readLength = source.read(result, destOffset+readSourceSize, (int) (sourceSize-readSourceSize))) != -1) {
				digest.update(result, destOffset+readSourceSize, readLength);
				readSourceSize+= readLength;
				if(readLength==0) {
					if(source.read() != -1) readSourceSize++;
					break;
				}
				
			}
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?");
			
		} else {
			// otherwise, hash segments
			this.segmentDigest.reset();
			
			// add file size + positive sign as compressed mode indicator
			ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).putLong(sourceSize);
			
			// calculate segment size (input size for each hash)
			// if necessary, start hashing 1 byte more which will later be dropped so we hash exactly sourceSize bytes 
			long segmentSize = sourceSize / hashCount;
			int overflowSegmentCount = (int) (sourceSize - segmentSize*hashCount);
			if(overflowSegmentCount > 0) segmentSize++;
			
			// allocate buffer.
			byte[] buf = new byte[16384];
			
			// prepare indices
			long readSourceSize = 0;
			long previouslyReadSegmentSize = 0;
			int readLength = 0;
			int segmentIndex = 0;
			int resultIndex = LONG_SIZE + digestLength;
			
			// read all input
			while((readLength = source.read(buf)) != -1) {
				readSourceSize+= readLength;
				if(readSourceSize > sourceSize) throw new IllegalArgumentException("read more bytes than sourceSize originally provided. Maybe the resource changed?");
				int readIndex = 0;
				digest.update(buf, readIndex, readLength);
				
				// if enough bytes for one hash have been accumulated then calculate the digest now
				while(previouslyReadSegmentSize + readLength >= segmentSize) {
					// if more bytes than needed have been accumulated, ignore them for now
					int limit = (int) (segmentSize - previouslyReadSegmentSize);
					
					// calculate digest 
					this.segmentDigest.update(buf, readIndex, limit);
					System.arraycopy(this.segmentDigest.digest(), 0, result, resultIndex, digestLength);
					resultIndex+= digestLength;
					
					// drop the additional byte from the segmentSize if enough overflowing segments have been processed
					segmentIndex++;
					if(segmentIndex==overflowSegmentCount) segmentSize--;
					
					// mark the bytes as read
					previouslyReadSegmentSize = 0;
					readLength-= limit;
					readIndex+= limit;
				}
				
				// if not enough bytes for one hash(segment) have been accumulated, just update
				if(readLength > 0) {
					this.segmentDigest.update(buf, readIndex, readLength);
					previouslyReadSegmentSize+= readLength;
				}
			}
			
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?");
			
		}
		
		// put one digest over the whole stream into the result
		System.arraycopy(this.digest.digest(), 0, result, LONG_SIZE, digestLength);
		
		System.out.println(Utils.bytesToHex(result));
		
		return result;
	}

}
