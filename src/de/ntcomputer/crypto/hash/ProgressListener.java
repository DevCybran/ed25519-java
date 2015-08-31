package de.ntcomputer.crypto.hash;

public interface ProgressListener {
	
	public void onProgress(long progress, long limit);

}
