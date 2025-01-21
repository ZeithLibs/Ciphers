package org.zeith.crypto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * The ServerShake class facilitates the server-side portion of a cryptographic handshake.
 * It generates a public-private key pair and provides functionality to generate and process
 * cryptographic data for secure communication with a client.
 */
public class ServerShake
{
	private final KeyPair pair;
	
	/**
	 * Constructs a new ServerShake instance using the specified key generation algorithm.
	 *
	 * @param algorithm
	 * 		the name of the key pair generation algorithm (e.g., "RSA").
	 *
	 * @throws NoSuchAlgorithmException
	 * 		if the specified algorithm is invalid or unavailable.
	 */
	public ServerShake(String algorithm)
			throws NoSuchAlgorithmException
	{
		this(KeyPairGenerator.getInstance(algorithm));
	}
	
	/**
	 * Constructs a new ServerShake instance using the provided {@link KeyPairGenerator}.
	 *
	 * @param algorithm
	 * 		a configured {@link KeyPairGenerator}.
	 *
	 * @throws NoSuchAlgorithmException
	 * 		if the algorithm associated with the {@link KeyPairGenerator} is invalid.
	 */
	public ServerShake(KeyPairGenerator algorithm)
			throws NoSuchAlgorithmException
	{
		this.pair = algorithm.generateKeyPair();
	}
	
	/**
	 * Retrieves the public key from the key pair.
	 *
	 * @return the generated {@link PublicKey}.
	 */
	public PublicKey getPublicKey()
	{
		return pair.getPublic();
	}
	
	/**
	 * Generates the server's handshake data, which consists of the encoded public key.
	 * This is what you should be sending off to clients to create {@link ClientShake}.
	 *
	 * @return a byte array containing the encoded public key.
	 */
	public byte[] generateServerShake()
	{
		return getPublicKey().getEncoded();
	}
	
	/**
	 * Processes the client's handshake data and generates a {@link ServerCipher} for communication.
	 *
	 * @param clientShake
	 * 		the encrypted data sent by the client.
	 *
	 * @return an instance of {@link ServerCipher} for secure communication.
	 *
	 * @throws GeneralSecurityException
	 * 		if decryption or key processing fails.
	 */
	public ServerCipher generateCipher(byte[] clientShake)
			throws GeneralSecurityException
	{
		Cipher c = Cipher.getInstance(pair.getPublic().getAlgorithm());
		c.init(Cipher.DECRYPT_MODE, pair.getPrivate());
		
		ByteArrayInputStream bais = new ByteArrayInputStream(c.doFinal(clientShake));
		
		byte[] algo = new byte[bais.read()];
		byte[] key = new byte[bais.read()];
		try
		{
			bais.read(algo);
			bais.read(key);
		} catch(IOException e)
		{
			// Shouldn't really happen...
			throw new RuntimeException(e);
		}
		
		return new ServerCipher(new SecretKeySpec(key, new String(algo, StandardCharsets.UTF_8)));
	}
}