import org.zeith.crypto.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Base64;

public class TestAES
{
	public static void main(String[] args)
			throws GeneralSecurityException, IOException
	{
		String password = "superSecretPassword123";
		
		ICipher cipher = new AESCipher(password);
		
		String plaintext = "Hello world! :)";
		byte[] encrypted = cipher.encrypt(plaintext.getBytes());
		
		cipher = new AESCipher(password);
		
		byte[] decrypted = cipher.decrypt(encrypted);
		
		System.out.println("Plaintext: " + plaintext);
		System.out.println("Encrypted (Base64): " + Base64.getEncoder().encodeToString(encrypted));
		System.out.println("Decrypted: " + new String(decrypted));
	}
}