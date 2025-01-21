package org.zeith.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

/**
 * The ClientCipher class handles encryption and decryption operations for the client-side
 * of a cryptographic handshake and communication.
 */
public class ClientCipher
		implements ICipher
{
	private final PublicKey publicKey;
	private final SecretKey secretKey;
	private final Cipher cipher;
	
	/**
	 * Constructs a ClientCipher using the provided public and secret keys.
	 *
	 * @param publicKey
	 * 		the server's {@link PublicKey}.
	 * @param secretKey
	 * 		the client's symmetric {@link SecretKey}.
	 *
	 * @throws GeneralSecurityException
	 * 		if cipher initialization fails.
	 */
	public ClientCipher(PublicKey publicKey, SecretKey secretKey)
			throws GeneralSecurityException
	{
		this.publicKey = publicKey;
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
	
	/**
	 * Generates a client handshake message encrypted with the server's public key.
	 * Send this to server to create {@link ServerCipher}.
	 *
	 * @return a byte array representing the encrypted handshake data.
	 *
	 * @throws GeneralSecurityException
	 * 		if encryption or key handling fails.
	 */
	public byte[] generateClientShake()
			throws GeneralSecurityException
	{
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		
		try
		{
			byte[] arr = secretKey.getAlgorithm().getBytes(StandardCharsets.UTF_8);
			byte[] arr2 = secretKey.getEncoded();
			baos.write(arr.length);
			baos.write(arr2.length);
			baos.write(arr);
			baos.write(arr2);
		} catch(IOException ioe)
		{
			ioe.printStackTrace();
		}
		
		Cipher c = Cipher.getInstance(publicKey.getAlgorithm());
		c.init(Cipher.ENCRYPT_MODE, publicKey);
		
		return c.doFinal(baos.toByteArray());
	}
}