package org.zeith.crypto;

import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * The ServerCipher class provides encryption and decryption operations using a symmetric key
 * derived from the server-client handshake.
 */
public class ServerCipher
		implements ICipher
{
	private final SecretKey secretKey;
	private final Cipher cipher;
	
	/**
	 * Constructs a ServerCipher using the provided secret key.
	 *
	 * @param secretKey
	 * 		the symmetric {@link SecretKey} for encryption and decryption.
	 *
	 * @throws GeneralSecurityException
	 * 		if initialization of the cipher fails.
	 */
	public ServerCipher(SecretKey secretKey)
			throws GeneralSecurityException
	{
		this.secretKey = secretKey;
		this.cipher = Cipher.getInstance(secretKey.getAlgorithm());
	}
	
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
	@Override
	public byte[] encrypt(byte[] data)
			throws GeneralSecurityException
	{
		return encrypt(data, 0, data.length);
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
	@Override
	public byte[] decrypt(byte[] data)
			throws GeneralSecurityException
	{
		return decrypt(data, 0, data.length);
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
	@Override
	public byte[] encrypt(byte[] data, int off, int len)
			throws GeneralSecurityException
	{
		cipher.init(Cipher.ENCRYPT_MODE, secretKey);
		return cipher.doFinal(data, off, len);
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
	@Override
	public byte[] decrypt(byte[] data, int off, int len)
			throws GeneralSecurityException
	{
		cipher.init(Cipher.DECRYPT_MODE, secretKey);
		return cipher.doFinal(data, off, len);
	}
}