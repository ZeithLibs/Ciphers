package org.zeith.crypto;

import javax.crypto.*;
import java.io.*;
import java.security.GeneralSecurityException;

/**
 * ICipher defines the interface for symmetric encryption and decryption operations.
 *
 * @see ServerCipher
 * @see ClientCipher
 */
public interface ICipher
{
	/**
	 * Encrypts the provided data.
	 *
	 * @param data
	 * 		the data to encrypt.
	 *
	 * @return the encrypted data.
	 *
	 * @throws GeneralSecurityException
	 * 		if encryption fails.
	 */
	default byte[] encrypt(byte[] data)
			throws GeneralSecurityException
	{
		return newCipher(CipherMode.ENCRYPT).doFinal(data);
	}
	
	/**
	 * Decrypts the provided data.
	 *
	 * @param data
	 * 		the data to decrypt.
	 *
	 * @return the decrypted data.
	 *
	 * @throws GeneralSecurityException
	 * 		if decryption fails.
	 */
	default byte[] decrypt(byte[] data)
			throws GeneralSecurityException
	{
		return newCipher(CipherMode.DECRYPT).doFinal(data);
	}
	
	/**
	 * Encrypts a subset of the provided data.
	 *
	 * @param data
	 * 		the data to encrypt.
	 * @param off
	 * 		the starting offset in the data.
	 * @param len
	 * 		the number of bytes to encrypt.
	 *
	 * @return the encrypted data.
	 *
	 * @throws GeneralSecurityException
	 * 		if encryption fails.
	 */
	default byte[] encrypt(byte[] data, int off, int len)
			throws GeneralSecurityException
	{
		return newCipher(CipherMode.ENCRYPT).doFinal(data, off, len);
	}
	
	/**
	 * Decrypts a subset of the provided data.
	 *
	 * @param data
	 * 		the data to decrypt.
	 * @param off
	 * 		the starting offset in the data.
	 * @param len
	 * 		the number of bytes to decrypt.
	 *
	 * @return the decrypted data.
	 *
	 * @throws GeneralSecurityException
	 * 		if decryption fails.
	 */
	default byte[] decrypt(byte[] data, int off, int len)
			throws GeneralSecurityException
	{
		return newCipher(CipherMode.DECRYPT).doFinal(data, off, len);
	}
	
	default CipherInputStream stream(InputStream input)
			throws GeneralSecurityException
	{
		return new CipherInputStream(input, newCipher(CipherMode.DECRYPT));
	}
	
	default CipherOutputStream stream(OutputStream output)
			throws GeneralSecurityException
	{
		return new CipherOutputStream(output, newCipher(CipherMode.ENCRYPT));
	}
	
	/**
	 * Creates a fresh copy of this cipher ready to perform encryption/decryption.
	 *
	 * @param mode
	 * 		the mode of this cipher
	 *
	 * @return a new configured cipher instance.
	 */
	Cipher newCipher(CipherMode mode)
			throws GeneralSecurityException;
}