/* SENG 2250 - ASSIGNMENT 3
 * Author: Harrison Rebesco 
 * Student Number: c3237487  
 * Date: 01/11/19
 * Description: Simulates a Server interacting with a Client - demonstrating DHE (integrated with RSA) handshake, and two data exchanges using CBC-MAC and CTR-MODE.
 */

import java.net.*;
import java.io.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Server
{
	public static void main(String[] args) throws Exception
	{
		EncryptionManager e = new EncryptionManager();
		BigInteger serverID = e.randomValue();
		BigInteger sessionID = e.randomValue();

		System.out.println("---- SERVER: ----\n");
	
		/**	ESTABLISHING CONNECTION	**************/
		ServerSocket ss = new ServerSocket(1234);
		Socket s = ss.accept();
		/*****************************************/
		
		System.out.println("---- HANDSHAKE: ----\n");
		
		/** READING CLIENT SETUP REQUEST ************************************/
		System.out.println("> READING setup_request FROM CLIENT...");
		InputStreamReader isr = new InputStreamReader(s.getInputStream());
		BufferedReader br = new BufferedReader(isr);
		
		String input = br.readLine();
		System.out.println("- setup_request: " + input + "\n");
		/********************************************************************/
		
		/**	SENDING RSA PUBLIC KEY & RSA MODULUS ****************************/
		PrintWriter pw = new PrintWriter(s.getOutputStream());
		
		BigInteger [] RSA = e.rsaValues();
		BigInteger rsaModulus = RSA[0];
		BigInteger rsaPublicKey = RSA[1];
		BigInteger rsaPrivateKey = RSA[2];
		
		System.out.println("> SENDING rsa_public_key AND rsa_modulus TO CLIENT... \n");
		pw.println(rsaPublicKey + " " + rsaModulus);
		pw.flush();
		/********************************************************************/
		
		/** READING CLIENT ID **********************************/
		System.out.println("> READING client_id FROM CLIENT:");
		
		input = br.readLine();
		BigInteger clientID = new BigInteger(input);
		System.out.println("- client_id: " + clientID + "\n");
		/******************************************************/
		
		/** SEND SERVER ID & SESSION ID ***************************************/
		System.out.println("> SENDING server_id AND session_id TO CLIENT...\n");
		pw.println(serverID + " " + sessionID);
		pw.flush();
		/**********************************************************************/
		
		/** EPHEMERAL DH EXCHANGE ****************************************************/
		//GENERATE DH PRIVATE KEY 
		System.out.println("> GENERATING server_dhe_private_key...");
		BigInteger dheBase = e.getBaseDHE();
		BigInteger dheModulus = e.getModDHE();
		BigInteger serverPrivateKey = e.randomValue(); 
		System.out.println("- server_dhe_private_key: " + serverPrivateKey + "\n");

		//GENERATE SERVER SECRET 
		System.out.println("> GENERATING server_secret...");
		BigInteger serverSecret = e.fastModExp(dheBase, serverPrivateKey, dheModulus);
		System.out.println("- server_secret: " + serverSecret + "\n");
		
		//HASH SERVER SECRET 
		System.out.println("> HASHING server_secret...");
		BigInteger hashedServerSecret = e.SHA256(serverSecret); 
		System.out.println("- hashed_server_secret: " + hashedServerSecret + "\n");
		
		//GENERATE RSA SIGNTURE 
		System.out.println("> GENERATING rsa_signature...");
		BigInteger rsaSignature = e.fastModExp(hashedServerSecret, rsaPrivateKey, rsaModulus); //encoding secret with privateKey to assign signature 
		System.out.println("- rsa_signature: " + rsaSignature + "\n");
		
		//SEND INFORMATION 
		System.out.println("> SENDING dhe_base, dhe_modulus, server_secret, rsa_signature TO CLIENT...\n");
		pw.println(serverSecret + " " + rsaSignature);
		pw.flush();
		/*****************************************************************************/
		
		/** FINISHED, CHECK SHARED KEY *****************************************************/
		//READ CLIENT SECRET 
		System.out.println("> READING client_secret FROM CLIENT...");
		input = br.readLine();
		BigInteger clientSecret = new BigInteger(input);
		System.out.println("- client_secret: " + clientSecret + "\n");
		
		//GENERATE DHE PUBLIC KEY 
		System.out.println("> GENERATING server_dhe_public_key...");
		BigInteger serverPublicKey = e.fastModExp(clientSecret, serverPrivateKey, dheModulus);
		System.out.println("- server_dhe_public_key: " + serverPublicKey + "\n");
		
		//HASH WITH PUBLIC KEY TO VERIFY 
		System.out.println("> GENERATING server_shared_hash...");
		BigInteger sharedHash= e.SHA256(serverPublicKey); //this acts as shared key 
		System.out.println("- server_shared_hash:" + sharedHash + "\n");
		
		//SENDING SHARED HASH 
		System.out.println("> SENDING server_shared_hash TO CLIENT...\n");
		pw.println(sharedHash);
		pw.flush();
		
		//READING CLIENT SHARED HASH 
		System.out.println("> READING client_shared_hash FROM CLIENT...");
		input = br.readLine();
		BigInteger clientSharedHash = new BigInteger(input);
		System.out.println("- client_shared_hash:" + clientSharedHash + "\n");	
		/************************************************************************************/
		
		System.out.println("---- END OF HANDSHAKE: ----\n");
		System.out.println("---- DATA EXCHANGE: ----\n");
	
		/** FIRST DATA EXCHANGE ************************************************************/ 
		System.out.println("> STARTING FIRST DATA EXCHANGE:\n");
		
		//ENCRYPTING MESSAGE VIA CTR MODE 
		
		//generating secret key based on public key used for encryption/decryption 
		String keyString = serverPublicKey.toString().substring(0, 16);		
        byte [] keyByte = keyString.getBytes();
		SecretKeySpec secretKey = new SecretKeySpec(keyByte, "AES");
		
		//generate message 
		System.out.println("> GENERATING server_message...");
		String message = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccdddddddddddddddd";
		System.out.println("- server_message: " + message + "\n");
		
		System.out.println("> ENCRYPTING server_message TO PROVIDE CONFIDENTIALITY...");
		
		//break message into 16 byte chunks
		String p1 = message.substring(0, 16);
		String p2 = message.substring(16, 32);
		String p3 = message.substring(32, 48);
		String p4 = message.substring(48, 64);
			
		//create iv counts 0 - 3
		byte[] iv1 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		byte[] iv2 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
		byte[] iv3 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };
		byte[] iv4 = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3 };
		
		//convert to string for AES decryption
		String ivStr1 = new String(iv1);
		String ivStr2 = new String(iv2);
		String ivStr3 = new String(iv3);
		String ivStr4 = new String(iv4);
		
		//encrypt plaintext 
		String CTR1 = e.encrypt(ivStr1, secretKey); //encrypt iv 
		String c1 = e.xor(p1, CTR1, 16); //xor with plaintext 
		String h1 = e.bytesToHex(c1.getBytes()); //convert to hexadecimal 
		
		String CTR2 = e.encrypt(ivStr2, secretKey); //encrypt iv 
		String c2 = e.xor(p2, CTR2, 16); //xor with plaintext 
		String h2 = e.bytesToHex(c2.getBytes()); //convert to hexadecimal 
		
		String CTR3 = e.encrypt(ivStr3, secretKey); //encrypt iv 
		String c3 = e.xor(p3, CTR3, 16); //xor with plaintext 
		String h3 = e.bytesToHex(c3.getBytes()); //convert to hexadecimal 
		
		String CTR4 = e.encrypt(ivStr4, secretKey); //encrypt iv 
		String c4 = e.xor(p4, CTR4, 16); //xor with plaintext 
		String h4 = e.bytesToHex(c4.getBytes()); //convert to hexadecimal 
			
		String hexadecimalEncryption = h1 + h2 + h3 + h4; //base 64 encryption
		System.out.println("- encrypted_message: " + hexadecimalEncryption + "\n");
		
		//GENERATING CBC MAC TO VERIFY INTEGRITY OF MESSAGE (using plaintext message above)
		
		System.out.println("> GENERATING server_mac TO PROVIDE INTEGRITY...");
		
		//first round encryption (no xor required)
		String MAC1 = e.encrypt(p1, secretKey);
		
		//second round encryption (xor m2 with e1)
		String x1 = e.xor(p2, MAC1, 16); //xor the second message segment with first encryption 
		String MAC2 = e.encrypt(x1, secretKey); //encrypt 
		
		//third round encryption (xor m3 with e2)
		String x2 = e.xor(p3, MAC2, 16); //xor the third message segment with second encryption 
		String MAC3 = e.encrypt(x2, secretKey); //encrypt 
		
		//fourth round encryption (xor m4 with e2)
		String x3 = e.xor(p4, MAC3, 16); //xor the fourth message segment with third encryption 
		String MAC4 = e.encrypt(x3, secretKey); //last round of encryption is the mac signature 
	
		System.out.println("- server_mac: " + MAC4 + "\n");
		
		//SEND SERVER MESSAGE AND CBC MAC TO CLIENT 
		System.out.println("> SENDING encrypted_message AND server_mac TO CLIENT...\n");
		pw.println(hexadecimalEncryption + " " + MAC4);
		pw.flush();
		
		System.out.println("> FIRST DATA EXCHANGE COMPLETE.\n");
		/************************************************************************************/
		
		/** SECOND DATA EXCHANGE ************************************************************/
		System.out.println("> STARTING SECOND DATA EXCHANGE:\n");
		
		//READING INPUT FROM SERVER 
		System.out.println("> READING encrypted_message AND client_mac FROM CLIENT...");
		input = br.readLine();
		String[] inputArray = input.split(" ");
		String encryptedMessage = inputArray[0];
		String clientMAC = inputArray[1];
		
		System.out.println("- encrypted_message: " + encryptedMessage);
		System.out.println("- client_mac: " + clientMAC + "\n");
		
		//DECRYPTION VIA CTR MODE 
		System.out.println("> DECRYPTING encrypted_message...");
		
		//break encrypted message into 16 byte chunks (it is encrypted to hexadecimal therefore 32 chars = 16 bytes)
		c1 = encryptedMessage.substring(0, 32);		
		c2 = encryptedMessage.substring(32, 64);
		c3 = encryptedMessage.substring(64, 96);
		c4 = encryptedMessage.substring(96, 128);
		
		//***using iv data declared above***
		
		//decrypt ciphertext 
		CTR1 = e.encrypt(ivStr1, secretKey); //encrypt iv 
		String a1 = e.hexToAscii(c1); //convert hex to ascii
		String d1 = e.xor(CTR1, a1, 16); //xor with converted ciphertext 
		h1 = e.bytesToHex(d1.getBytes()); //convert byte to hex 
		p1 = e.hexToAscii(h1); //convert hex to plaintext 
		
		CTR2 = e.encrypt(ivStr2, secretKey); //encrypt iv 
		String a2 = e.hexToAscii(c2); //convert hext to ascii
		String d2 = e.xor(CTR2, a2, 16); //xor with converted ciphertext 
		h2 = e.bytesToHex(d2.getBytes()); //convert byte to hex 
		p2 = e.hexToAscii(h2); //convert hex to plaintext 
		
		CTR3 = e.encrypt(ivStr3, secretKey); //encrypt iv 
		String a3 = e.hexToAscii(c3); //convert hex to ascii 
		String d3 = e.xor(CTR3, a3, 16); //xor with converted ciphertext 
		h3 = e.bytesToHex(d3.getBytes()); //convert byte to hex 
		p3 = e.hexToAscii(h3); //convert hex to plaintext 
		
		CTR4 = e.encrypt(ivStr4, secretKey); //encrypt iv 
		String a4 = e.hexToAscii(c4); //convert hext to ascii 
		String d4 = e.xor(CTR4, a4, 16); //xor with converted ciphertext 
		h4 = e.bytesToHex(d4.getBytes()); //convert byte to hex 
		p4 = e.hexToAscii(h4); //convert hex to plaintext 
		
		String decryptedMessage = p1 + p2 + p3 + p4; //convert to ascii 
		System.out.println("- decrypted_message: " + decryptedMessage + "\n"); //print the decrypted message 
		
		//GENERATING CBC-MAC
		System.out.println("> GENERATING server_mac TO VERIFY decrypted_message INTEGRITY...");
		
		//first round encryption (no xor required)
		MAC1 = e.encrypt(p1, secretKey);
		
		//second round encryption (xor m2 with e1)
		x1 = e.xor(p2, MAC1, 16); //xor the second message segment with first encryption 
		MAC2 = e.encrypt(x1, secretKey); //encrypt 
		
		//third round encryption (xor m3 with e2)
		x2 = e.xor(p3, MAC2, 16); //xor the third message segment with second encryption 
		MAC3 = e.encrypt(x2, secretKey); //encrypt 
		
		//fourth round encryption (xor m4 with e2)
		x3 = e.xor(p4, MAC3, 16); //xor the fourth message segment with third encryption 
		MAC4 = e.encrypt(x3, secretKey); //last round of encryption is the mac signature 
		
		System.out.println("- server_mac: " + MAC4 + "\n");
		System.out.println("> SECOND DATA EXCHANGE COMPLETE.\n");
		/************************************************************************************/
		
		System.out.println("---- END OF DATA EXCHANGE: ----\n");
	}
}