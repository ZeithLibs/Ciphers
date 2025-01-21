package org.zeith.crypto.ws;

import org.zeith.crypto.*;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.concurrent.*;

/**
 * A {@link WebSocket.Listener} implementation for the client side that supports encrypted communication.
 * This class extends {@link CipheredWebsocketListener} to handle cryptographic setup and data processing.
 */
public class ClientWebsocketListener
		extends CipheredWebsocketListener
{
	private final String algorithm;
	
	/**
	 * Constructs a {@code ClientWebsocketListener}.
	 *
	 * @param algorithm
	 * 		the cryptographic algorithm to use for communication.
	 * @param delegate
	 * 		the WebSocket listener to delegate non-encrypted messages to.
	 */
	public ClientWebsocketListener(String algorithm, WebSocket.Listener delegate)
	{
		super(delegate);
		this.algorithm = algorithm;
	}
	
	/**
	 * Handles incoming binary data, performing cryptographic setup before giving control to delegate.
	 *
	 * @param webSocket
	 * 		the WebSocket that received the binary data.
	 * @param data
	 * 		the binary data buffer.
	 * @param last
	 * 		indicates if this is the last part of a multi-part message.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this message.
	 */
	@Override
	public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last)
	{
		if(cipher == null)
		{
			if(data.getInt() == MAGIC_NUMBER)
			{
				byte[] alg = new byte[data.getShort()];
				data.get(alg);
				
				byte[] key = new byte[data.getShort()];
				data.get(key);
				
				try
				{
					ClientKeyGen ckg = new ClientKeyGen(new String(alg, StandardCharsets.UTF_8), key);
					ClientCipher cs = ckg.generateCipher(algorithm);
					cipher = cs;
					
					key = cs.generateClientShake();
					
					ByteBuffer ndata = ByteBuffer.allocate(4 + 2 + key.length);
					ndata.putInt(MAGIC_NUMBER);
					ndata.putShort((short) key.length);
					ndata.put(key);
					webSocket.sendBinary(ndata, true);
				} catch(GeneralSecurityException e)
				{
					throw new WebSocketDecryptionException("Failed to initialize client cipher", e);
				}
			}
			
			webSocket.request(1L);
			return CompletableFuture.completedFuture(null);
		}
		
		return super.onBinary(webSocket, data, last);
	}
}