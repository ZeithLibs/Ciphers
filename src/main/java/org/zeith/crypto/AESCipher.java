package org.zeith.crypto;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.GeneralSecurityException;

public class AESCipher
		implements ICipher
{
	private final SecretKey key;
	private final IvParameterSpec iv;
	
	public AESCipher(SecretKey key, byte[] ivBytes)
	{
		if(ivBytes.length != 16)
			throw new IllegalArgumentException("IV must be 16 bytes for AES.");
		this.key = key;
		this.iv = new IvParameterSpec(ivBytes);
	}
	
	public AESCipher(String password, byte[] salt, byte[] ivBytes)
			throws GeneralSecurityException
	{
		if(ivBytes.length != 16)
			throw new IllegalArgumentException("IV must be 16 bytes for AES.");
		
		this.key = deriveKey(password, salt, 128); // or 256 bits if supported
		this.iv = new IvParameterSpec(ivBytes);
	}
	
	public AESCipher(String password)
			throws GeneralSecurityException
	{
		// Derive key from password (no salt!)
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), new byte[16], 1, 128);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] keyBytes = factory.generateSecret(spec).getEncoded();
		this.key = new SecretKeySpec(keyBytes, "AES");
		
		// Fixed IV (all zeros, 16 bytes)
		this.iv = new IvParameterSpec(new byte[16]);
	}
	
	private static SecretKey deriveKey(String password, byte[] salt, int keySize)
			throws GeneralSecurityException
	{
		PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 65536, keySize);
		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		byte[] keyBytes = factory.generateSecret(spec).getEncoded();
		return new SecretKeySpec(keyBytes, "AES");
	}
	
	@Override
	public Cipher newCipher(CipherMode mode)
			throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(mode.mode, key, iv);
		return cipher;
	}
}