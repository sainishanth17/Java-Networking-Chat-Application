package chat;

import java.awt.BorderLayout;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.swing.*;

import encryption.Encryption;

import java.security.*;


public class ChatServer extends JFrame {

	private static final String RSA = "RSA";
	private Key privateKey;
	
	public ChatServer() {
	
		super("Chat Server");

		try {
			privateKey = Encryption.readPrivateKey("keypairs/pkcs8_key");
		} catch (Exception e) {
			e.printStackTrace();
			System.err.println("problem loading private key: " + e.getMessage());
			System.exit(1);
		}
		
		
	}
	
	

	
	public static void main(String[] args) {
		ChatServer chatServer = new ChatServer();
	}
	
	
}


