 #include <cryptoauth.h>

AtEcc108 ecc = AtEcc108();


const byte numChars = 32;
char receivedChars[numChars];
char tempChars[numChars];

char messageFromPC[numChars] = {0};
char message2FromPC[numChars] = {0};
int integerFromPC = 0;
int float2FromPC = 0;
int floatFromPC = 0;
boolean newData = false;

void setup(){
  Serial.begin(9600);

  Serial.println();

  ecc.enableDebug(&Serial);
  
  Serial.println("User Menu");
  Serial.println("Enter your choice");
  Serial.println("1. User Input (Choice,YOUR MSG) ");
  Serial.println("2. Create Hash Digest and print it (Choice,Your MSG)");
  Serial.println("3. Create Signature of message and print it (Choice,Your Msg,Private Key Slot");
  Serial.println("4. Check authentication (Choice,Your Message,Public Key Slot)");
  Serial.println("5. Debug mode (Choice,Your Message,Public Key Slot,Private Key Slot,Debug Message)");

  
}

void loop(){
   recvWithStartEndMarkers();
   if (newData == true) {
     strcpy(tempChars, receivedChars);
     parseData();
     showParsedData();
     newData = false;

     sha256_hash_t hash1;
     char sig[64];
     char pub[64];
     if(integerFromPC==1){
      Serial.print("debug message: ");
      Serial.println(message2FromPC);
      Serial.print("Public Key Slot: ");
      Serial.println(floatFromPC);
      Serial.print("Private Key Slot: ");
      Serial.println(float2FromPC);
      Serial.println();
     
     }
     
     else if(integerFromPC==2){
      Serial.println();
      sha256(&hash1, messageFromPC, sizeof(messageFromPC));
      hexify("Message Digest for message Sent: ", &hash1[0], sizeof(hash1));
     }
     
     else if(integerFromPC==3){
      Serial.print("Private Key Slot: ");
      Serial.println(floatFromPC);
      Serial.println();
      
      sha256(&hash1, messageFromPC, sizeof(messageFromPC));
     //hexify("Message Digest for message Sent: ", &hash1[0], sizeof(hash1));

     if (0 != ecc.sign(&hash1[0], sizeof(hash1),floatFromPC))
           Serial.println("Fail sign");
      else
      {
          memcpy (sig, ecc.rsp.getPointer(), sizeof(sig));
          hexify("Signature1 Created:", (const uint8_t *) sig, sizeof(sig));
       
       }
     }

     else if(integerFromPC==4){
      Serial.print("Public Key Slot: ");
      Serial.println(floatFromPC);
      Serial.println();
      
     sha256(&hash1, messageFromPC, sizeof(messageFromPC));
     hexify("Message Digest for message Sent: ", &hash1[0], sizeof(hash1));

     if (0 != ecc.sign(&hash1[0], sizeof(hash1),floatFromPC))
           Serial.println("Fail sign");
      else
      {
          memcpy (sig, ecc.rsp.getPointer(), sizeof(sig));
          hexify("Signature1 Created:", (const uint8_t *) sig, sizeof(sig));
       
       }

     if(0!=ecc.hash_verify(messageFromPC, sizeof(messageFromPC),floatFromPC,(const uint8_t *) sig)){
        memcpy (pub, ecc.rsp.getPointer(), sizeof(pub));
        Serial.println();
          hexify("Public Key:", (const uint8_t *) pub, sizeof(pub));
        Serial.println("\n Verification failed");
       }
      else{
          memcpy (pub, ecc.rsp.getPointer(), sizeof(pub));
          Serial.println();
          hexify("Public Key:", (const uint8_t *) pub, sizeof(pub));
          Serial.println("\n Verification Success\n");
       }
     }
     else if(integerFromPC==5){
      Serial.print("Public Key Slot: ");
      Serial.println(floatFromPC);
      Serial.print("Private Key Slot: ");
      Serial.println(float2FromPC);
  
     
     sha256(&hash1, messageFromPC, sizeof(messageFromPC));
     hexify("\nMessage Digest for message Sent: ", &hash1[0], sizeof(hash1));

     if (0 != ecc.sign(&hash1[0], sizeof(hash1),float2FromPC))
           Serial.println("Fail sign");
      else
      {
          memcpy (sig, ecc.rsp.getPointer(), sizeof(sig));
          hexify("Signature1 Created:", (const uint8_t *) sig, sizeof(sig));
       
       }

     if(0!=ecc.hash_verify(message2FromPC, sizeof(message2FromPC),floatFromPC,(const uint8_t *) sig)){
        memcpy (pub, ecc.rsp.getPointer(), sizeof(pub));
        Serial.println();
          hexify("Public Key:", (const uint8_t *) pub, sizeof(pub));
        Serial.println("\n Verification failed");
       }
      else{
          memcpy (pub, ecc.rsp.getPointer(), sizeof(pub));
          Serial.println();
          hexify("Public Key:", (const uint8_t *) pub, sizeof(pub));
          Serial.println("\n Verification Success\n");
       }
     }
      
     
   }
}

void recvWithStartEndMarkers() {
    static boolean recvInProgress = false;
    static byte ndx = 0;
    char startMarker = '(';
    char endMarker = ')';
    char rc;

    while (Serial.available() > 0 && newData == false) {
        rc = Serial.read();

        if (recvInProgress == true) {
            if (rc != endMarker) {
                receivedChars[ndx] = rc;
                ndx++;
                if (ndx >= numChars) {
                    ndx = numChars - 1;
                }
            }
            else {
                receivedChars[ndx] = '\0'; 
                recvInProgress = false;
                ndx = 0;
                newData = true;
            }
        }

        else if (rc == startMarker) {
            recvInProgress = true;
        }
    }
}

void parseData() {      
    
    char * strtokIndx; 

    strtokIndx = strtok(tempChars,",");     
    integerFromPC = atoi(strtokIndx);  
 
    strtokIndx = strtok(NULL, ","); 
    strcpy(messageFromPC, strtokIndx);
       
    strtokIndx = strtok(NULL, ",");
    floatFromPC = atoi(strtokIndx); 

    strtokIndx = strtok(NULL, ",");
    float2FromPC = atoi(strtokIndx); 
     
    strtokIndx = strtok(NULL, ",");
    strcpy(message2FromPC, strtokIndx);

}

void showParsedData() {
     Serial.print("Your Choice: ");
    Serial.println(integerFromPC);
    Serial.print("Your Message: ");
    Serial.println(messageFromPC);
   
}

void hexify(const char *str, const uint8_t *hex, unsigned int len)
{

  int i;
  Serial.write(str);

  Serial.println();

  for (i = 0; i < len; i++)
    {
      static char tmp[4] = {};
      if (i > 0)
        Serial.write(" ");

      sprintf(tmp, "0x%02X", hex[i]);
      Serial.write(tmp);
    }

  Serial.write("\n");

}



