package org.zeith.crypto.ws;

import org.zeith.crypto.*;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.concurrent.*;

/**
 * A WebSocket listener implementation for the server side that supports encrypted communication.
 * This class extends {@link CipheredWebsocketListener} to handle cryptographic setup and data processing.
 */
public class ServerWebsocketListener
		extends CipheredWebsocketListener
{
	private final ServerKeyGen key;
	
	/**
	 * Constructs a {@code ServerWebsocketListener} using the default cryptographic algorithm.
	 *
	 * @param delegate
	 * 		the WebSocket listener to delegate non-encrypted messages to.
	 *
	 * @throws NoSuchAlgorithmException
	 * 		if the default cryptographic algorithm is not available.
	 */
	public ServerWebsocketListener(WebSocket.Listener delegate)
			throws NoSuchAlgorithmException
	{
		this(new ServerKeyGen("RSA"), delegate);
	}
	
	/**
	 * Constructs a {@code ServerWebsocketListener} with a specified key generator.
	 *
	 * @param key
	 * 		the server key generator.
	 * @param delegate
	 * 		the WebSocket listener to delegate non-encrypted messages to.
	 */
	public ServerWebsocketListener(ServerKeyGen key, WebSocket.Listener delegate)
	{
		super(delegate);
		this.key = key;
	}
	
	/**
	 * Handles the WebSocket connection opening event. Sends the server's public key to the client.
	 *
	 * @param webSocket
	 * 		the WebSocket that has been opened.
	 */
	@Override
	public void onOpen(WebSocket webSocket)
	{
		// Once the websocket opens, we send the server's public key immediately
		
		var k = key.generateServerShake();
		var alg = key.getAlgorithm().getBytes(StandardCharsets.UTF_8);
		ByteBuffer buf = ByteBuffer.allocate(4 + 2 + alg.length + 2 + k.length);
		buf.putInt(MAGIC_NUMBER);
		buf.putShort((short) alg.length).put(alg);
		buf.putShort((short) k.length).put(k);
		
		webSocket.sendBinary(buf.flip(), true)
				 // Pass the onOpen only after our packet was sent!
				 .thenAccept(super::onOpen);
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
				byte[] key = new byte[data.getShort()];
				data.get(key);
				try
				{
					this.cipher = this.key.generateCipher(key);
				} catch(GeneralSecurityException e)
				{
					throw new RuntimeException(e);
				}
			}
			
			webSocket.request(1L);
			return CompletableFuture.completedFuture(null);
		}
		return super.onBinary(webSocket, data, last);
	}
}