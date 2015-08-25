package de.ntcomputer.crypto.hash;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashCondenser {
	public static final int DEFAULT_OUTPUT_SIZE = 512*1024;
	private final MessageDigest digest;
	private final int outputSize;
	private final int digestLength;
	private final int hashCount;
	
	public static HashCondenser getInstance(MessageDigest md, int outputSize) {
		return new HashCondenser(md, outputSize);
	}
	
	public static HashCondenser getInstance(int outputSize) throws NoSuchAlgorithmException {
		return new HashCondenser(MessageDigest.getInstance("SHA-512"), outputSize);
	}
	
	public static HashCondenser getInstance(MessageDigest md) {
		return new HashCondenser(md, DEFAULT_OUTPUT_SIZE);
	}
	
	public static HashCondenser getInstance() throws NoSuchAlgorithmException {
		return new HashCondenser(MessageDigest.getInstance("SHA-512"), DEFAULT_OUTPUT_SIZE);
	}
	
	private HashCondenser(MessageDigest md, int outputSize) {
		this.digest = md;
		this.outputSize = outputSize;
		digestLength = md.getDigestLength();
		if(digestLength==0) throw new IllegalArgumentException("could not determine message digest length (returned 0)");
		if(this.outputSize < this.digestLength) throw new IllegalArgumentException("output size is less than message digest length");
		this.hashCount = this.outputSize / digestLength;
	}
	
	/**
	 * Computes a condensed version of the input (data).
	 * 
	 * @see #compute(InputStream, long)
	 * @param data
	 * @return
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
	 * If sourceSize is not greater than this object's outputSize, then a 0-padded copy of the source will be returned.
	 * Otherwise, a 0-padded concatenation of hashes for segments of the source will be returned.
	 * 
	 * @param source
	 * @param sourceSize the exact number of bytes which can be read from source 
	 * @return
	 * @throws IOException when source throws an IOException
	 * @throws IllegalArgumentException if sourceSize happens not to be the same as source's size
	 */
	public byte[] compute(InputStream source, long sourceSize) throws IOException, IllegalArgumentException {
		// create result buffer
		byte[] result = new byte[this.outputSize];
		Arrays.fill(result, (byte) 0x00);
		
		if(sourceSize <= this.outputSize) {
			// copy source directly if short enough
			int readSourceSize = 0;
			int readLength;
			while((readLength = source.read(result, readSourceSize, (int) (sourceSize-readSourceSize))) != -1) {
				readSourceSize+= readLength;
				if(readLength==0) {
					if(source.read() != -1) readSourceSize++;
					break;
				}
			}
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?"); 
		} else {
			// otherwise, hash segments
			
			// calculate segment size (input size for each hash)
			// if necessary, start hashing 1 byte more which will later be dropped so we hash exactly sourceSize bytes 
			long segmentSize = sourceSize / hashCount;
			int overflowSegmentCount = (int) (sourceSize - segmentSize*hashCount);
			if(overflowSegmentCount > 0) segmentSize++;
			
			// allocate buffer. Not too large.
			int bufCapacity = (int) Math.min(1024L, segmentSize);
			byte[] buf = new byte[bufCapacity];
			
			// prepare indices
			long readSourceSize = 0;
			long readSegmentSize = 0;
			int readLength = 0;
			int segmentIndex = 0;
			int resultIndex = 0;
			
			// read all input
			while((readLength = source.read(buf)) != -1) {
				readSourceSize+= readLength;
				if(readSourceSize > sourceSize) throw new IllegalArgumentException("read more bytes than sourceSize originally provided. Maybe the resource changed?");
				readSegmentSize+= readLength;
				
				if(readSegmentSize < segmentSize) {
					// if not enough bytes for one hash(segment) have been accumulated, just update
					this.digest.update(buf, 0, readLength);
				} else {
					// if more bytes than needed have been accumulated, ignore them for now
					int limit = (int) (readLength - (readSegmentSize-segmentSize));
					
					// calculate digest 
					this.digest.update(buf, 0, limit);
					System.arraycopy(this.digest.digest(), 0, result, resultIndex, digestLength);
					resultIndex+= digestLength;
					
					// drop the additional byte from the segmentSize if enough overflowing segments have been processed
					segmentIndex++;
					if(segmentIndex==overflowSegmentCount) segmentSize--;
					
					// if more bytes than needed have been accumulated, update the next digest now
					readSegmentSize = readLength - limit;
					if(readSegmentSize > 0) this.digest.update(buf, limit, (int) readSegmentSize);
				}
			}
			
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?");
			
		}
		
		return result;
	}

}
