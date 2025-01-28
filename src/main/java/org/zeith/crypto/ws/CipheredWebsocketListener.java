package org.zeith.crypto.ws;

import org.zeith.crypto.ICipher;

import java.net.http.WebSocket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import java.util.concurrent.*;

/**
 * A WebSocket listener that supports encrypted communication by delegating events
 * and decrypting messages transparently. This listener is intended to be extended
 * to add specific cryptographic setup and additional handling.
 */
public class CipheredWebsocketListener
		implements WebSocket.Listener
{
	/**
	 * A constant value used as a magic number in the cryptographic handshake process.
	 */
	public static final int MAGIC_NUMBER = 0xAEF85217;
	
	private final WebSocket.Listener delegate;
	protected WebSocket webSocket;
	protected ICipher cipher;
	
	/**
	 * Constructs a {@code CipheredWebsocketListener} with a specified delegate.
	 *
	 * @param delegate
	 * 		the WebSocket listener to delegate non-encrypted events to.
	 */
	public CipheredWebsocketListener(WebSocket.Listener delegate)
	{
		this.delegate = delegate;
	}
	
	/**
	 * Sends a text message through the WebSocket after the connection cipher has been established.
	 *
	 * @param text
	 * 		the plain text message to be sent.
	 * @param last
	 * 		indicates if this is the last part of a multipart message.
	 */
	public CompletableFuture<WebSocket> sendText(String text, boolean last)
	{
		try
		{
			// Encoded base64 -> decoded UTF-8 text
			text = Base64.getEncoder().encodeToString(cipher.encrypt(text.getBytes(StandardCharsets.UTF_8)));
		} catch(GeneralSecurityException e)
		{
			throw new WebSocketDecryptionException("Failed to encrypt WebSocket text message.", e);
		}
		
		return webSocket.sendText(text, last);
	}
	
	/**
	 * Sends a binary message through the WebSocket after the connection cipher has been established.
	 *
	 * @param message
	 * 		the binary message buffer to be sent.
	 * @param last
	 * 		indicates if this is the last part of a multipart message.
	 */
	public CompletableFuture<WebSocket> sendBinary(ByteBuffer message, boolean last)
	{
		return webSocket.sendBinary(encrypt(message), last);
	}
	
	/**
	 * Sends a ping message through the WebSocket after the connection cipher has been established.
	 *
	 * @param ping
	 * 		the ping binary message buffer to be sent.
	 */
	public CompletableFuture<WebSocket> sendPing(ByteBuffer ping)
	{
		return webSocket.sendPing(encrypt(ping));
	}
	
	/**
	 * Sends a pong message through the WebSocket after the connection cipher has been established.
	 *
	 * @param ping
	 * 		the pong binary message buffer to be sent.
	 */
	public CompletableFuture<WebSocket> sendPong(ByteBuffer ping)
	{
		return webSocket.sendPong(encrypt(ping));
	}
	
	/**
	 * Gets the current WebSocket instance.
	 *
	 * @return the WebSocket instance, or {@code null} if the connection is closed.
	 */
	public WebSocket getWebSocket()
	{
		return webSocket;
	}
	
	/**
	 * Handles the WebSocket connection opening event and stores the WebSocket instance.
	 *
	 * @param webSocket
	 * 		the WebSocket that has been opened.
	 */
	@Override
	public void onOpen(WebSocket webSocket)
	{
		this.webSocket = webSocket;
		delegate.onOpen(webSocket);
	}
	
	/**
	 * Handles incoming text messages by decrypting them and delegating the event.
	 *
	 * @param webSocket
	 * 		the WebSocket that received the message.
	 * @param data
	 * 		the encrypted text data, base64-encoded.
	 * @param last
	 * 		indicates if this is the last part of a multi-part message.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this message.
	 */
	@Override
	public CompletionStage<?> onText(WebSocket webSocket, CharSequence data, boolean last)
	{
		try
		{
			// Encoded base64 -> decoded UTF-8 text
			data = new String(cipher.decrypt(Base64.getDecoder().decode(data.toString())), StandardCharsets.UTF_8);
		} catch(GeneralSecurityException e)
		{
			throw new WebSocketDecryptionException("Failed to decrypt WebSocket text message.", e);
		}
		
		delegate.onText(webSocket, data, last);
		return CompletableFuture.completedFuture(null);
	}
	
	/**
	 * Handles incoming binary messages by decrypting them and delegating the event.
	 *
	 * @param webSocket
	 * 		the WebSocket that received the message.
	 * @param data
	 * 		the encrypted binary data.
	 * @param last
	 * 		indicates if this is the last part of a multi-part message.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this message.
	 */
	@Override
	public CompletionStage<?> onBinary(WebSocket webSocket, ByteBuffer data, boolean last)
	{
		delegate.onBinary(webSocket, decrypt(data), last);
		return CompletableFuture.completedFuture(null);
	}
	
	/**
	 * Handles incoming ping frames by decrypting them and delegating the event.
	 *
	 * @param webSocket
	 * 		the WebSocket that received the ping.
	 * @param message
	 * 		the encrypted ping message.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this message.
	 */
	@Override
	public CompletionStage<?> onPing(WebSocket webSocket, ByteBuffer message)
	{
		delegate.onPing(webSocket, decrypt(message));
		return CompletableFuture.completedFuture(null);
	}
	
	/**
	 * Handles incoming pong frames by decrypting them and delegating the event.
	 *
	 * @param webSocket
	 * 		the WebSocket that received the pong.
	 * @param message
	 * 		the encrypted pong message.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this message.
	 */
	@Override
	public CompletionStage<?> onPong(WebSocket webSocket, ByteBuffer message)
	{
		delegate.onPong(webSocket, decrypt(message));
		return CompletableFuture.completedFuture(null);
	}
	
	/**
	 * Handles the WebSocket closing event and clears the WebSocket reference.
	 *
	 * @param webSocket
	 * 		the WebSocket that is closing.
	 * @param statusCode
	 * 		the status code for the closure.
	 * @param reason
	 * 		the reason for the closure.
	 *
	 * @return a {@link CompletionStage} representing the asynchronous processing of this event.
	 */
	@Override
	public CompletionStage<?> onClose(WebSocket webSocket, int statusCode, String reason)
	{
		this.webSocket = null;
		return delegate.onClose(webSocket, statusCode, reason);
	}
	
	/**
	 * Handles WebSocket errors by delegating the event.
	 *
	 * @param webSocket
	 * 		the WebSocket that encountered the error.
	 * @param error
	 * 		the error that occurred.
	 */
	@Override
	public void onError(WebSocket webSocket, Throwable error)
	{
		delegate.onError(webSocket, error);
	}
	
	/**
	 * Decrypts a binary message using the established cipher.
	 *
	 * @param message
	 * 		the encrypted binary message buffer.
	 *
	 * @return a decrypted {@link ByteBuffer}.
	 *
	 * @throws RuntimeException
	 * 		if decryption fails.
	 */
	protected ByteBuffer decrypt(ByteBuffer message)
	{
		byte[] tmp = new byte[message.remaining()];
		message.get(tmp);
		try
		{
			message = ByteBuffer.wrap(cipher.decrypt(tmp));
		} catch(GeneralSecurityException e)
		{
			throw new WebSocketDecryptionException("Decryption failed", e);
		}
		return message;
	}
	
	/**
	 * Encrypts a binary message using the established cipher.
	 *
	 * @param message
	 * 		the binary message buffer to be encrypted.
	 *
	 * @return an encrypted {@link ByteBuffer}.
	 *
	 * @throws RuntimeException
	 * 		if encryption fails.
	 */
	protected ByteBuffer encrypt(ByteBuffer message)
	{
		byte[] tmp = new byte[message.remaining()];
		message.get(tmp);
		try
		{
			message = ByteBuffer.wrap(cipher.encrypt(tmp));
		} catch(GeneralSecurityException e)
		{
			throw new WebSocketDecryptionException("Encryption failed", e);
		}
		return message;
	}
	
	@Override
	public String toString()
	{
		return "ServerWebsocketListener{" +
				"delegate=" + delegate +
				'}';
	}
}