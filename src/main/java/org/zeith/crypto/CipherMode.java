package org.zeith.crypto;

import javax.crypto.Cipher;

public enum CipherMode
{
	ENCRYPT(Cipher.ENCRYPT_MODE),
	DECRYPT(Cipher.DECRYPT_MODE);
	
	public final int mode;
	
	CipherMode(int mode)
	{
		this.mode = mode;
	}
}