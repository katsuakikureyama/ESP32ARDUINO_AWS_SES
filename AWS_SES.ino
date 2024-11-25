#include "utility.h"
#include "send_ses.h"

String fromAddress="aws address";
SimpleList toAddresses;
SimpleList ccAddresses;
SimpleList bccAddresses;
String subject="mail subject";
String body="mail body";

String wifiSSID="";
String wifiPassword="";
String awsAccessKey="";
String awsSecretKey="";
String awsRegion="";
String awsHost="";
String awsService="";


void setup() {
  Serial.begin(115200);

  delay(1000);
  
  toAddresses.add("address");
  ccAddresses.add("cc");
  bccAddresses.add("bcc");


  WiFi.begin(wifiSSID.c_str(), wifiPassword.c_str());
  int c = 120;
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
    c--;
    if(c==0){
     ESP.restart();
     }
  }
  Serial.println("Connected to WiFi");

  client.setCACert(AWS_CERT_CA);
  configTime(0, 0, "pool.ntp.org", "time.nist.gov");

  
}


void loop() {
  String body = " Test";
  
  sendSES(toAddresses, ccAddresses, bccAddresses, subject, body);
  
  delay(60000);  // 1分間隔で送信
}
