import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import org.zeith.crypto.ClientCipher;
import org.zeith.crypto.ClientKeyGen;
import org.zeith.crypto.ServerCipher;
import org.zeith.crypto.ServerKeyGen;

public class TestRSA
{
	public static void main(String[] args)
	{
		try
		{
			// Create a server shake with RSA
			ServerKeyGen serv1 = new ServerKeyGen("RSA");
			
			// Generate a public key to send to client:
			byte[] sr_shake = serv1.generateServerShake();
			
			// Create a client shake with RSA using received public key:
			ClientKeyGen client1 = new ClientKeyGen("RSA", sr_shake);
			
			// Converting the client shake to a cipher with symmetrical key:
			ClientCipher cc = client1.generateCipher("AES");
			
			// Generate an encrypted (with public key) message of symmetrical
			// key to send back to server:
			byte[] cl_shake = cc.generateClientShake();
			
			// Create a server cipher using encrypted message to work with
			// symmetrical key:
			ServerCipher sc = serv1.generateCipher(cl_shake);
			
			// Now let's test if it works....
			
			// This is our test message
			String message = "Hello World!";
			byte[] messageBytes = message.getBytes(StandardCharsets.UTF_8);
			
			// Encrypt message with ServerCipher
			// This message can be sent over network safely
			byte[] enc = sc.encrypt(messageBytes);
			
			// Print encoded message to console and see how it looks when
			// encrypted:
			System.out.println("----------- enc -----------");
			System.out.println(new String(enc));
			System.out.println("---------------------------");
			
			// Decrypt message with ClientCipher
			// This message restores back
			byte[] dec = cc.decrypt(enc);
			
			System.out.println(); // Separate two prints
			
			// Print decoded message to console and ensure it works!
			System.out.println("----------- dec -----------");
			System.out.println(new String(dec));
			System.out.println("---------------------------");
		} catch(GeneralSecurityException e)
		{
			e.printStackTrace();
		}
	}
}