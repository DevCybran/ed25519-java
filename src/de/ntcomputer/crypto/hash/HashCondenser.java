package de.ntcomputer.crypto.hash;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HashCondenser {
	public static final int DEFAULT_OUTPUT_SIZE = 512*1024;
	private static final int LONG_SIZE = Long.SIZE/8;
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
		this.hashCount = (this.outputSize - LONG_SIZE) / digestLength;
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
		
		if(sourceSize <= this.outputSize-LONG_SIZE) {
			// copy source directly if short enough
			
			// add file size + negative sign as direct mode indicator
			ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).putLong(-sourceSize);
			
			int readSourceSize = 0;
			int readLength;
			while((readLength = source.read(result, LONG_SIZE+readSourceSize, (int) (sourceSize-readSourceSize))) != -1) {
				readSourceSize+= readLength;
				if(readLength==0) {
					if(source.read() != -1) readSourceSize++;
					break;
				}
			}
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?");
			
		} else {
			// otherwise, hash segments
			
			// add file size + positive sign as compressed mode indicator
			ByteBuffer.wrap(result).order(ByteOrder.BIG_ENDIAN).putLong(sourceSize);
			
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
			long previouslyReadSegmentSize = 0;
			int readLength = 0;
			int segmentIndex = 0;
			int resultIndex = LONG_SIZE;
			
			// read all input
			while((readLength = source.read(buf)) != -1) {
				readSourceSize+= readLength;
				if(readSourceSize > sourceSize) throw new IllegalArgumentException("read more bytes than sourceSize originally provided. Maybe the resource changed?");
				int readIndex = 0;
				
				// if enough bytes for one hash have been accumulated then calculate the digest now
				while(previouslyReadSegmentSize + readLength >= segmentSize) {
					// if more bytes than needed have been accumulated, ignore them for now
					int limit = (int) (segmentSize - previouslyReadSegmentSize);
					
					// calculate digest 
					this.digest.update(buf, readIndex, limit);
					System.arraycopy(this.digest.digest(), 0, result, resultIndex, digestLength);
					resultIndex+= digestLength;
					
					// drop the additional byte from the segmentSize if enough overflowing segments have been processed
					segmentIndex++;
					if(segmentIndex==overflowSegmentCount) segmentSize--;
					
					// mark the bytes as read
					previouslyReadSegmentSize = 0;
					readLength-= limit;
				}
				
				// if not enough bytes for one hash(segment) have been accumulated, just update
				if(readLength > 0) {
					this.digest.update(buf, readIndex, readLength);
					previouslyReadSegmentSize+= readLength;
				}
			}
			
			if(readSourceSize != sourceSize) throw new IllegalArgumentException("read not as many bytes as sourceSize originally provided. Maybe the resource changed?");
			
		}
		
		return result;
	}

}
