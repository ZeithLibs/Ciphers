package org.zeith.crypto;

import javax.crypto.*;
import java.security.GeneralSecurityException;

/**
 * The ServerCipher class provides encryption and decryption operations using a symmetric key
 * derived from the server-client handshake.
 */
public class ServerCipher
		implements ICipher
{
	private final SecretKey secretKey;
	
	/**
	 * Constructs a ServerCipher using the provided secret key.
	 *
	 * @param secretKey
	 * 		the symmetric {@link SecretKey} for encryption and decryption.
	 */
	public ServerCipher(SecretKey secretKey)
	{
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
}