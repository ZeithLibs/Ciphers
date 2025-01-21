package org.zeith.crypto;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

/**
 * The ClientShake class facilitates the client-side portion of a cryptographic handshake,
 * including processing the server's handshake data and generating a cipher.
 */
public class ClientShake
{
	private final PublicKey key;
	
	/**
	 * Constructs a ClientShake instance using the provided server handshake data and algorithm.
	 *
	 * @param algorithm
	 * 		the name of the key factory algorithm (e.g., "RSA").
	 * @param serverShake
	 * 		the server's handshake data (encoded public key).
	 *
	 * @throws GeneralSecurityException
	 * 		if key processing fails.
	 */
	public ClientShake(String algorithm, byte[] serverShake)
			throws GeneralSecurityException
	{
		this(KeyFactory.getInstance(algorithm), serverShake);
	}
	
	/**
	 * Constructs a ClientShake instance using the provided KeyFactory and server handshake data.
	 *
	 * @param algorithm
	 * 		a configured {@link KeyFactory}.
	 * @param serverShake
	 * 		the server's handshake data (encoded public key).
	 *
	 * @throws GeneralSecurityException
	 * 		if key processing fails.
	 */
	public ClientShake(KeyFactory algorithm, byte[] serverShake)
			throws GeneralSecurityException
	{
		this.key = algorithm.generatePublic(new X509EncodedKeySpec(serverShake));
	}
	
	/**
	 * Generates a client-side cipher for secure communication using the specified algorithm.
	 *
	 * @param algorithm
	 * 		the name of the key generation algorithm (e.g., "AES").
	 *
	 * @return an instance of {@link ClientCipher}.
	 *
	 * @throws GeneralSecurityException
	 * 		if cipher initialization fails.
	 */
	public ClientCipher generateCipher(String algorithm)
			throws GeneralSecurityException
	{
		return generateCipher(KeyGenerator.getInstance(algorithm));
	}
	
	/**
	 * Generates a client-side cipher for secure communication using the provided KeyGenerator.
	 *
	 * @param algorithm
	 * 		a configured {@link KeyGenerator}.
	 *
	 * @return an instance of {@link ClientCipher}.
	 *
	 * @throws GeneralSecurityException
	 * 		if cipher initialization fails.
	 */
	public ClientCipher generateCipher(KeyGenerator algorithm)
			throws GeneralSecurityException
	{
		return new ClientCipher(key, algorithm.generateKey());
	}
}