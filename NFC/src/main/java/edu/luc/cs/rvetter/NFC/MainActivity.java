package edu.luc.cs.rvetter.NFC;

import android.annotation.TargetApi;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.IntentFilter;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.nfc.tech.NdefFormatable;
import android.os.Build;
import android.os.Bundle;
import android.app.Activity;
import android.os.Parcelable;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.Charset;

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class MainActivity extends Activity implements View.OnClickListener {
    // True = ready to write to devices
    private boolean inWriteMode;
    // Button which sets write mode
    private Button writeButton;
    // Text that displays all messages
    private TextView interactionText;


    private EditText secretKeyText;
    //String secretDecryptionKey = "1234567812345678";

    // Connects to NFC devices
    private NfcAdapter nfcAdapter;
    // A blank ndefMessage used for NFC and Beam, may be adopted to other techs
    private NdefMessage ndefMessage;
    // Intent listener that grabs nfc events
    PendingIntent pendingIntent;
    IntentFilter[] filters;
    // Listener filters for nfc enable devices or tags
    IntentFilter tagDetected;



    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        //TextView that we'll use to output messages to screen
        interactionText = (TextView)findViewById(R.id.text_view);
        secretKeyText = (EditText) findViewById(R.id.secretKeyText);

        Intent intent = getIntent();
        if(intent.getType() != null && intent.getType().equals(MimeType.NFC_MIME)) {
            readMessage(intent);
        }

        // grab NFC Adapter
        nfcAdapter = NfcAdapter.getDefaultAdapter(this);

        // button that starts the write procedure
        writeButton = (Button)findViewById(R.id.write_button);
        writeButton.setOnClickListener(this);
    }

    /**
     * Reads NFC Tag and displays a message.
     */
    public void readMessage(Intent intent) {
        Parcelable[] rawMsgs = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES);
        if(rawMsgs.length > 0)
        {
                NdefMessage msg = (NdefMessage) rawMsgs[rawMsgs.length-1];
                NdefRecord cardRecord = msg.getRecords()[0];
                //String messageRead = new String(cardRecord.getPayload());
                try {
                    String secretKey = secretKeyText.getText().toString();
                    // decrypt the array
                    byte[] decryptedMessage = decryptMessage(secretKey, cardRecord.getPayload());
                    // set the text view for the decrypted message
                    String temp = new String(decryptedMessage);
                    //Toast.makeText(getApplicationContext(), temp), Toast.LENGTH_LONG).show();
                    displayMessage("The message on this card says:\n" + temp);

                } catch (Exception e) {
                    displayMessage("Message cannot be decrypted! Incorrect key or corrupted message error");
                }
        }
    }

    public static byte[] decryptMessage(String secretKeyString, byte[] encryptedMsg) throws  Exception {
        // generate AES secret key from the user input string
        Key key = generateKey(secretKeyString);
        // get the cipher algorithm for AES
        Cipher c = Cipher.getInstance("AES");
        // specify the decryption mode
        c.init(Cipher.DECRYPT_MODE, key);
        // decrypt the message
        byte[] decryptValue = c.doFinal(encryptedMsg);

        return decryptValue;
    }



    public void onClick(View v) {
        if(v.getId() == R.id.write_button) {
            displayMessage("Touch and hold tag against phone to write.");
            inWriteMode = true;
            createMessage();
        }
    }

    @Override
    protected void onResume() {
        super.onResume();
        enableAllReceiverTechnology();
    }

    @Override
    protected void onPause() {
        super.onPause();
        disableAllReceiverTechnology();
    }

    /**
     * Called when blank tag is scanned executing the PendingIntent
     */
    @Override
    public void onNewIntent(Intent intent) {
        if(inWriteMode) {
            // write to newly scanned tag
            Tag tag = intent.getParcelableExtra(NfcAdapter.EXTRA_TAG);
            if(writeTag(tag))
            {
                inWriteMode = false;
            }
        }
        else{
               readMessage(intent);
        }
    }

    /**
     * Force this Activity to get NFC events first
     */
    private void enableAllReceiverTechnology()
    {
        // Enable NFC/Android Beam Events
        // set up a PendingIntent to open the app when a tag is scanned
        pendingIntent = PendingIntent.getActivity(this, 0,
                new Intent(this, getClass()).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP), 0);
        tagDetected = new IntentFilter(NfcAdapter.ACTION_TAG_DISCOVERED);
        filters = new IntentFilter[] { tagDetected };
        nfcAdapter.enableForegroundDispatch(this, pendingIntent, filters, null);
    }

    private void disableAllReceiverTechnology()
    {
        // Disable NFC
        nfcAdapter.disableForegroundDispatch(this);
    }

    private void createMessage()
    {
        String secretKey = secretKeyText.getText().toString();
        byte[] encryptedMessage = encryptMessage(secretKey, getMessageText());
        String finalMessage = byte2hex(encryptedMessage);

        // record to launch Play Store if app is not installed
        NdefRecord appRecord = NdefRecord.createApplicationRecord("edu.luc.cs.rvetter.NFC");
        // record that contains custom text data, using custom MIME_TYPE
        byte[] payload = encryptedMessage;
        byte[] mimeBytes = MimeType.NFC_MIME.getBytes(Charset.forName("US-ASCII"));
        NdefRecord messageRecord = new NdefRecord(NdefRecord.TNF_MIME_MEDIA, mimeBytes,
                new byte[0], payload);
        NdefMessage potentialNdefMessage = new NdefMessage(new NdefRecord[] { messageRecord, appRecord});

        // Check permissions to enable correct sending technologies
        checkPermissions(potentialNdefMessage);
    }


    public static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for(int i = 0; i <b.length; i++) {
            stmp = Integer.toHexString(b[i] & 0xFF);
            if (stmp.length() == 1) {
                hs += ("0" + stmp);
            }
            else {
                hs += stmp;
            }
        }
        return hs.toUpperCase();
    }

    public static byte[] encryptMessage(String secretKeyString, String msgContentString) {
        try {
            byte[] returnArray;

            // generate AES secret key from user input
            Key key = generateKey(secretKeyString);

            // specify the cipher algorithm using AES
            Cipher c = Cipher.getInstance("AES");

            // specify encryption mode
            c.init(Cipher.ENCRYPT_MODE, key);

            // encrypt
            returnArray = c.doFinal(msgContentString.getBytes());

            return returnArray;
        } catch (Exception e) {
            e.printStackTrace();
            byte[] returnArray = null;
            return returnArray;
        }
    }
    private static Key generateKey(String secretKeyString) throws Exception {
        // generate secret key from string
        Key key = new SecretKeySpec(secretKeyString.getBytes(), "AES");
        return key;
    }

    private void checkPermissions(NdefMessage potentialNdefMessage)
    {
        CheckBox andoidBeam = (CheckBox) findViewById(R.id.beamCheckBox);
        if(andoidBeam.isChecked())
        {
            nfcAdapter.setNdefPushMessage(potentialNdefMessage, this);
        }
        else
        {
            nfcAdapter.setNdefPushMessage(null, this);
        }
        CheckBox nfc = (CheckBox) findViewById(R.id.nfcCheckBox);
        if(nfc.isChecked())
        {
            ndefMessage = potentialNdefMessage;
        }
        else
        {
            ndefMessage = null;
        }
    }

    /**
     * Format a tag and write NDEF message
     */
    private boolean writeTag(Tag tag) {
        try {
            // see if tag is already NDEF formatted
            Ndef ndef = Ndef.get(tag);
            if (ndef != null) {
                ndef.connect();

                if (!ndef.isWritable()) {
                    displayMessage("Read-only tag.");
                    return false;
                }

                // work out how much space we need for the data
                int size = 0;
                try{
                    size = ndefMessage.toByteArray().length;
                }
                catch(Exception e){
                    displayMessage("Cannot write to NFC tag without permission");
                    return false;
                }
                if (ndef.getMaxSize() < size) {
                    displayMessage("Tag doesn't have enough free space.");
                    return false;
                }

                ndef.writeNdefMessage(ndefMessage);
                displayMessage("Tag written successfully.");
                return true;
            } else {
                // attempt to format tag
                NdefFormatable format = NdefFormatable.get(tag);
                if (format != null) {
                    try {
                        format.connect();
                        format.format(ndefMessage);
                        displayMessage("Tag written successfully!\nClose this app and scan tag.");
                        return true;
                    } catch (IOException e) {
                        displayMessage("Unable to format tag to NDEF.");
                        return false;
                    }
                } else {
                    displayMessage("Tag doesn't appear to support NDEF format.");
                    return false;
                }
            }
        } catch (Exception e) {
            displayMessage("Failed to write tag");
        }

        return false;
    }

    private String getMessageText() {
        EditText messageText = (EditText) findViewById( R.id.messageText);
        String messageToSend = messageText.getText().toString();
        return messageToSend;
    }

    private void displayMessage(String message)
    {
        interactionText.setText(message);
    }
}