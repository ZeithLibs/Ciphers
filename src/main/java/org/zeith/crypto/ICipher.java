package org.zeith.crypto;

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
	byte[] encrypt(byte[] data)
			throws GeneralSecurityException;
	
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
	byte[] decrypt(byte[] data)
			throws GeneralSecurityException;
	
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
	byte[] encrypt(byte[] data, int off, int len)
			throws GeneralSecurityException;
	
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
	byte[] decrypt(byte[] data, int off, int len)
			throws GeneralSecurityException;
}