package org.zeith.crypto.util;

import org.zeith.crypto.ICipher;

import java.io.*;
import java.nio.file.*;
import java.security.GeneralSecurityException;

public class FileCipher
{
	public static void encrypt(ICipher cipher, Path source, Path target, OpenOption... saveOptions)
			throws IOException
	{
		try(InputStream input = Files.newInputStream(source);
			OutputStream out = cipher.stream(Files.newOutputStream(target, saveOptions)))
		{
			input.transferTo(out);
		} catch(GeneralSecurityException e)
		{
			throw new IOException(e);
		}
	}
	
	public static void decrypt(ICipher cipher, Path source, Path target, OpenOption... saveOptions)
			throws IOException
	{
		try(InputStream input = cipher.stream(Files.newInputStream(source));
			OutputStream out = Files.newOutputStream(target, saveOptions))
		{
			input.transferTo(out);
		} catch(GeneralSecurityException e)
		{
			throw new IOException(e);
		}
	}
}