/* SENG 2250 - ASSIGNMENT 3
 * Author: Harrison Rebesco 
 * Student Number: c3237487  
 * Date: 01/11/19
 * Description: Simulates a Client interacting with a Server - demonstrating DHE (integrated with RSA) handshake, and two data exchanges using CBC-MAC and CTR-MODE.
 */

import java.net.*;
import java.io.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.security.SecureRandom;

public class Client
{
	
	public static void main(String[] args) throws Exception
	{
		EncryptionManager e = new EncryptionManager();
		BigInteger clientID = e.randomValue();
		
		/** ESTABLISHING CONNECTION *************/
		Socket s = new Socket("localhost", 1234);
		/****************************************/

		System.out.println("---- CLIENT: ----\n");
		
		/** SENDING SETUP REQUEST ******************************/
		System.out.println("---- HANDSHAKE: ----\n");
		
		PrintWriter pw = new PrintWriter(s.getOutputStream());
	
		System.out.println("> SENDING setup_request...\n");
		pw.println("hello");
		pw.flush();
		/*******************************************************/		
		
		/** READING SETUP *************************************************************/
		System.out.println("> READING rsa_public_key AND rsa_modulus FROM SERVER...");
		
		//setting up input readyer
		InputStreamReader isr = new InputStreamReader(s.getInputStream());
		BufferedReader br = new BufferedReader(isr);
		
		String input = br.readLine();
		String [] inputArray = input.split(" ");
		BigInteger rsaPublicKey = new BigInteger(inputArray[0]);
		BigInteger rsaModulus = new BigInteger(inputArray[1]);
		
		System.out.println("- rsa_public_key: " + rsaPublicKey);
		System.out.println("- rsa_modulus: " + rsaModulus + "\n");
		/*****************************************************************************/
		
		/** SENDING CLIENT ID **********************************************/
		System.out.println("> SENDING client_hello TO SERVER... \n");
		pw.println(clientID);
		pw.flush();
		/*******************************************************************/
		
		/** READING SERVER HELLO ***********************************************/
		System.out.println("> READING server_id AND session_id FROM SERVER...");
		
		input = br.readLine();
		inputArray = input.split(" ");
		BigInteger serverID = new BigInteger(inputArray[0]);
		BigInteger sessionID = new BigInteger(inputArray[1]);
		
		System.out.println("- server_id: " + serverID);
		System.out.println("- session_id: " + sessionID + "\n");
		/***********************************************************************/
		
		/** EPHEMERAL DH EXCHANGE ****************************************************************/
		// READING SERVER_SECRET & RSA_SIGNATURE 
		System.out.println("> READING server_secret AND encrypted_rsa_signature FROM SERVER...");
		
		input = br.readLine();
		inputArray = input.split(" ");
		BigInteger dheBase = e.getBaseDHE();
		BigInteger dheModulus = e.getModDHE();
		BigInteger serverSecret = new BigInteger(inputArray[0]); //hashed server secret in hexadecimal form 
		BigInteger rsaSignature = new BigInteger(inputArray[1]);
		
		System.out.println("- server_secret: " + serverSecret);
		System.out.println("- encrypted_rsa_signature: " + rsaSignature + "\n");
		
		System.out.println("> DECRYPTING rsa_signature...");
		BigInteger decryptedServerSecret = e.fastModExp(rsaSignature, rsaPublicKey, rsaModulus); 
		System.out.println("- decrypted_rsa_signature: " + decryptedServerSecret + "\n");
		
		System.out.println("> HASHING server_secret TO VERIFY decrypted_rsa_signature...");
		BigInteger verifyHash = e.SHA256(serverSecret); 
		System.out.println("- hashed_server_secret: " + verifyHash + "\n");
		
		// GENERATE & SEND CLIENT_SECRET 
		System.out.println("> GENERATING client_dhe_private_key...");
		BigInteger clientPrivateKey = e.randomValue(); 
		System.out.println("- client_dhe_private_key: " + clientPrivateKey + "\n");
		
		System.out.println("> GENERATING client_secret...");
		BigInteger clientSecret = e.fastModExp(dheBase, clientPrivateKey, dheModulus); //client dhe private key 
		System.out.println("- client_secret:" + clientSecret + "\n");
		
		System.out.println("> SENDING client_secret TO SERVER... \n");
		pw.println(clientSecret);
		pw.flush();
		/******************************************************************************************/
		
		/** FINISHED, CHECK SHARED KEY ******************************************************/
		//GENERATE DHE PUBLIC KEY 
		System.out.println("> GENERATING client_dhe_public_key...");
		BigInteger clientPublicKey = e.fastModExp(serverSecret, clientPrivateKey, dheModulus);
		System.out.println("- client_dhe_public_key: " + clientPublicKey + "\n");
		
		//HASH WITH SHARED KEY TO VERIFY 
		System.out.println("> GENERATING client_shared_hash...");
		BigInteger sharedKey = clientPublicKey; //in this case im hashing the public DHE key with the session ID so client can verify server
		BigInteger sharedHash = e.SHA256(sharedKey);
		System.out.println("- client_shared_hash:" + sharedHash + "\n");
		
		//SENDING SHARED HASH 
		System.out.println("> SENDING client_shared_hash TO SERVER...\n");
		pw.println(sharedHash);
		pw.flush();
		
		//READING SERVER SHARED HASH 
		System.out.println("> READING server_shared_hash FROM SERVER...");
		input = br.readLine();
		BigInteger serverSharedHash = new BigInteger(input);
		System.out.println("- server_shared_hash:" + serverSharedHash + "\n");
		/**************************************************************************************/
		
		System.out.println("---- END OF HANDSHAKE: ----\n");
		System.out.println("---- DATA EXCHANGE: ----\n");
		
		/** FIRST DATA EXCHANGE ***************************************************************/
		
		//generating secret key based on public key used for encryption/decryption 
		String keyString = clientPublicKey.toString().substring(0, 16);		
        byte [] keyByte = keyString.getBytes();
		SecretKeySpec secretKey = new SecretKeySpec(keyByte, "AES");	
		
		//FIRST EXCHANGE: 
		System.out.println("> STARTING FIRST DATA EXCHANGE:\n");
		
		//DECRYPTION VIA CTR MODE 
		System.out.println("> READING encrypted_message AND server_mac FROM SERVER...");
		input = br.readLine();
		inputArray = input.split(" ");
		String encryptedMessage = inputArray[0];
		String serverMAC = inputArray[1];
		
		System.out.println("- encrypted_message: " + encryptedMessage);
		System.out.println("- server_mac: " + serverMAC + "\n");
		
		//DECRYPT MESSAGE
		System.out.println("> DECRYPTING encrypted_message...");
		
		//break encrypted message into 16 byte chunks (it is encrypted to hexadecimal therefore 32 chars = 16 bytes)
		String c1 = encryptedMessage.substring(0, 32);		
		String c2 = encryptedMessage.substring(32, 64);
		String c3 = encryptedMessage.substring(64, 96);
		String c4 = encryptedMessage.substring(96, 128);
		
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
		
		//decrypt ciphertext 
		String CTR1 = e.encrypt(ivStr1, secretKey); //encrypt iv 
		String a1 = e.hexToAscii(c1); //convert hex to ascii
		String d1 = e.xor(CTR1, a1, 16); //xor with converted ciphertext 
		String h1 = e.bytesToHex(d1.getBytes()); //convert byte to hex 
		String p1 = e.hexToAscii(h1); //convert hex to plaintext 
		
		String CTR2 = e.encrypt(ivStr2, secretKey); //encrypt iv 
		String a2 = e.hexToAscii(c2); //convert hext to ascii
		String d2 = e.xor(CTR2, a2, 16); //xor with converted ciphertext 
		String h2 = e.bytesToHex(d2.getBytes()); //convert byte to hex 
		String p2 = e.hexToAscii(h2); //convert hex to plaintext 
		
		String CTR3 = e.encrypt(ivStr3, secretKey); //encrypt iv 
		String a3 = e.hexToAscii(c3); //convert hex to ascii 
		String d3 = e.xor(CTR3, a3, 16); //xor with converted ciphertext 
		String h3 = e.bytesToHex(d3.getBytes()); //convert byte to hex 
		String p3 = e.hexToAscii(h3); //convert hex to plaintext 
		
		String CTR4 = e.encrypt(ivStr4, secretKey); //encrypt iv 
		String a4 = e.hexToAscii(c4); //convert hext to ascii 
		String d4 = e.xor(CTR4, a4, 16); //xor with converted ciphertext 
		String h4 = e.bytesToHex(d4.getBytes()); //convert byte to hex 
		String p4 = e.hexToAscii(h4); //convert hex to plaintext 
		
		String decryptedMessage = p1 + p2 + p3 + p4; //convert to ascii 
		System.out.println("- decrypted_message: " + decryptedMessage + "\n"); //print the decrypted message 
		
		//GENERATING CBC-MAC
		
		System.out.println("> GENERATING client_mac TO VERIFY server_message INTEGRITY...");
		
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
	
		System.out.println("- client_mac: " + MAC4 + "\n");
		System.out.println("> FIRST DATA EXCHANGE COMPLETE.\n");
		/************************************************************************************/
		
		/** SECOND DATA EXCHANGE ************************************************************/
		System.out.println("> STARTING SECOND DATA EXCHANGE:\n");
		
		//ENCRYPTION VIA CTR MODE 
		
		//generate message 
		System.out.println("> GENERATING client_message...");
		String message = "eeeeeeeeeeeeeeeeffffffffffffffffgggggggggggggggghhhhhhhhhhhhhhhh";
		System.out.println("- client_message: " + message + "\n");
		
		System.out.println("> ENCRYPTING client_message TO PROVIDE CONFIDENTIALITY...");
		
		//break message into 16 byte chunks
		p1 = message.substring(0, 16);
		p2 = message.substring(16, 32);
		p3 = message.substring(32, 48);
		p4 = message.substring(48, 64);

		//re-use IV values declared earlier 
		
		//encrypt plaintext 
		CTR1 = e.encrypt(ivStr1, secretKey); //encrypt iv 
		c1 = e.xor(p1, CTR1, 16); //xor with plaintext 
		h1 = e.bytesToHex(c1.getBytes()); //convert to hexadecimal 
		
		CTR2 = e.encrypt(ivStr2, secretKey); //encrypt iv 
		c2 = e.xor(p2, CTR2, 16); //xor with plaintext 
		h2 = e.bytesToHex(c2.getBytes()); //convert to hexadecimal 
		
		CTR3 = e.encrypt(ivStr3, secretKey); //encrypt iv 
		c3 = e.xor(p3, CTR3, 16); //xor with plaintext 
		h3 = e.bytesToHex(c3.getBytes()); //convert to hexadecimal 
		
		CTR4 = e.encrypt(ivStr4, secretKey); //encrypt iv 
		c4 = e.xor(p4, CTR4, 16); //xor with plaintext 
		h4 = e.bytesToHex(c4.getBytes()); //convert to hexadecimal 
			
		String hexadecimalEncryption = h1 + h2 + h3 + h4; //base 64 encryption
		System.out.println("- encrypted_message: " + hexadecimalEncryption + "\n");
		
		//GENERATING CBC MAC TO VERIFY INTEGRITY OF MESSAGE (using plaintext message above)
		System.out.println("> GENERATING client_mac TO PROVIDE INTEGRITY...");
		
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
	
		System.out.println("- client_mac: " + MAC4 + "\n");
		
		//SEND CLIENT MESSAGE AND CBC MAC TO CLIENT 
		System.out.println("> SENDING encrypted_message AND client_mac TO SERVER...\n");
		pw.println(hexadecimalEncryption + " " + MAC4);
		pw.flush();
		
		System.out.println("> SECOND DATA EXCHANGE COMPLETE.\n");
		/*************************************************************************************/
		
		System.out.println("---- END OF DATA EXCHANGE: ----\n");
	}
}