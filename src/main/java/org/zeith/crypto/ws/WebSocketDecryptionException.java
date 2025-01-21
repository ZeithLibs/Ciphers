package org.zeith.crypto.ws;

public class WebSocketDecryptionException
		extends RuntimeException
{
	public WebSocketDecryptionException()
	{
		super();
	}
	
	public WebSocketDecryptionException(String message)
	{
		super(message);
	}
	
	public WebSocketDecryptionException(String message, Throwable cause)
	{
		super(message, cause);
	}
	
	public WebSocketDecryptionException(Throwable cause)
	{
		super(cause);
	}
	
	protected WebSocketDecryptionException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
	{
		super(message, cause, enableSuppression, writableStackTrace);
	}
}