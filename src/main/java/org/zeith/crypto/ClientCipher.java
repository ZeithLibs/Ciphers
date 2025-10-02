package org.zeith.crypto;

import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;

/**
 * The ClientCipher class handles encryption and decryption operations for the client-side
 * of a cryptographic handshake and communication.
 */
public class ClientCipher
		implements ICipher
{
	private final PublicKey publicKey;
	private final SecretKey secretKey;
	
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
	}
	
	@Override
	public Cipher newCipher(CipherMode mode)
			throws GeneralSecurityException
	{
		Cipher cipher = Cipher.getInstance(secretKey.getAlgorithm());
		cipher.init(mode.mode, secretKey);
		return cipher;
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