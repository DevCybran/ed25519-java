package de.ntcomputer.crypto.hash;

@FunctionalInterface
public interface ProgressListener {
	
	public void onProgress(long progress, long limit);

}
