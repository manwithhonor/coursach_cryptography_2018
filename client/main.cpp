#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/sha.h>
#include <iostream>
#include <fstream>
#include <string>
#include <assert.h>
#include <fcntl.h>
#include "debug.h"
#include <unistd.h>

unsigned int timeInterval = 2000000;

#define port	1100
std::string text2 = "second message";
std::string text4 = "foutrh message";
std::string nonceclient;

int clientId;
RSA* readPrivateKey() {
	std::ifstream in("/home/payalnik/share/private_client_"+std::to_string(clientId)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

RSA* readPublicKey() {
	std::ifstream in("/home/payalnik/share/public_server_"+std::to_string(clientId)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

RSA* readOwnPublickKey() {
	std::ifstream in("/home/payalnik/share/public_client_"+std::to_string(clientId)+".pem");
	std::string key((std::istreambuf_iterator<char>(in)), 
		std::istreambuf_iterator<char>());
  RSA *rsa = NULL;
  const char* c_string = key.c_str();
  BIO * keybio = BIO_new_mem_buf((void*)c_string, -1);
  if (keybio==NULL) {
      return 0;
  }
  rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
  return rsa;
}

bool RSASign( RSA* rsa, 
              const unsigned char* Msg, 
              size_t MsgLen,
              unsigned char** EncMsg, 
              size_t* MsgLenEnc) {
  EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
  EVP_PKEY* priKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(priKey, rsa);
  if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
      return false;
  }
  if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
      return false;
  }
  if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
      return false;
  }
  *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
  if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
      return false;
  }
  EVP_MD_CTX_cleanup(m_RSASignCtx);
  return true;
}

bool RSAVerifySignature( RSA* rsa, 
                         unsigned char* MsgHash, 
                         size_t MsgHashLen, 
                         const char* Msg, 
                         size_t MsgLen, 
                         bool* Authentic) {
  *Authentic = false;
  EVP_PKEY* pubKey  = EVP_PKEY_new();
  EVP_PKEY_assign_RSA(pubKey, rsa);
  EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

  if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
    return false;
  }
  if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
    return false;
  }
  int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
  if (AuthStatus==1) {
    *Authentic = true;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else if(AuthStatus==0){
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return true;
  } else{
    *Authentic = false;
    EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
    return false;
  }
}

void generateRandomNumber(std::string& random) {
	for (int i = 0; i < 10; i++)
		random.push_back((int)(49+rand()%9));
}

std::string generateMessageOne(const std::string& random) {
  std::string text1("firstpass ");
	std::string result = random + text1;
	
	return result;
}

void copyValue(unsigned char* m, int length, std::string& s) {
		for (int i = 0; i < length; i++)
			s.push_back(m[i]);
}

int EVP_PKEY_get_type(EVP_PKEY *pkey)
{
    ASSERT(pkey);
    if (!pkey)
        return NID_undef;

    return EVP_PKEY_type(pkey->type);
}

bool isValidRSAPublicKeyOnly(RSA *rsa) {
    //from rsa_ameth.c do_rsa_print : has a private key
    //from rsa_chk.c RSA_check_key : doesn't have n (modulus) and e (public exponent)
    if (!rsa || rsa->d || !rsa->n || !rsa->e) {
        return false;
    }
    return BN_is_odd(rsa->e) && !BN_is_one(rsa->e);
}

bool isValidPublicKeyOnly(EVP_PKEY *pkey) {
    //EVP_PKEY_get_type from http://stackoverflow.com/a/29885771/2692914
    int type = EVP_PKEY_get_type(pkey); //checks nullptr
    if (type != EVP_PKEY_RSA && type != EVP_PKEY_RSA2) {
        //not RSA
        return false;
    }

    RSA *rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        return false;
    }

    bool isValid = isValidRSAPublicKeyOnly(rsa);
    RSA_free(rsa);
    return isValid;
}


void process_connection(int socket, struct sockaddr_in& stSockAddr, std::string message, RSA* public_key, RSA* private_key, RSA* ownPublickKey) {
	char recv_buff[1024];
	int i32Res;
	memset(&stSockAddr, 0, sizeof (stSockAddr));

	stSockAddr.sin_family = PF_INET;
	stSockAddr.sin_port = htons(1100);
	i32Res = inet_pton(PF_INET, "127.0.0.1", &stSockAddr.sin_addr);

	if (connect(socket, (struct sockaddr*) &stSockAddr, sizeof (stSockAddr)) == -1) {
		std::cout<<"connection error\n"<<std::endl;
	} else {
	  printf("Connected\n");
	}
	
	int written_bytes = write(socket, message.c_str(), message.length());
	DEBUG_ONLY(std::cout<<"Written message : "<<message<<std::endl);
	usleep(timeInterval);
	DEBUG_ONLY(std::cout<<"Written size is : "<<message.length()<<std::endl);
	usleep(timeInterval);
	
	/**********client, server names**/
	std::string A_name = "serverA   ";
	std::string B = "client1   ";
	std::string nonceRB;
	for (int i = 0; i < (message.length() - 10); i++)
		nonceRB.push_back(message[i]);
	
	
	int read_bytes = read(socket, recv_buff, 400);
	DEBUG_ONLY(std::cout<<"Read size is : "<<read_bytes<<std::endl);
	
	/*****ensure key posession***/
	EVP_PKEY* pubKey  = EVP_PKEY_new();//-аллоцируется память для публичного ключа
  EVP_PKEY_assign_RSA(pubKey, public_key);
	DASSERT(isValidPublicKeyOnly(pubKey), "CLIENT IS IN POSESSION OF AN INVALID PUBLIC KEY");
	DEBUG_ONLY(std::cout<<"PUBLIC SERVER KEY VERIFICATION HAS PASSED"<<std::endl);
	usleep(timeInterval);
	/*****End********************/
	
	std::string received_nonceRA;
	std::string received_nonceRB;
	std::string received_A;
//	std::string A_name;
	
	int nonce_size = (read_bytes - 256 - 10)/2;
	std::cout<<"Nonce size : "<<nonce_size<<std::endl;
	usleep(timeInterval);
	for (int i = 0; i < nonce_size; i++)
		received_nonceRA.push_back(recv_buff[i]);
	for (int i = nonce_size; i < 2*nonce_size; i++)
		received_nonceRB.push_back(recv_buff[i]);
	for (int i = 2*nonce_size; i < 2*nonce_size + 10; i++)
		received_A.push_back(recv_buff[i]);

	DEBUG_ONLY(std::cout<<"Received A nonce : "<<received_nonceRA<<std::endl);
	usleep(timeInterval);
	DEBUG_ONLY(std::cout<<"Received B nonce : "<<received_nonceRB<<std::endl);
	usleep(timeInterval);
	DEBUG_ONLY(std::cout<<"Received A name : "<<received_A<<std::endl);
	usleep(timeInterval);

	
	std::string encrypted_message;
	for (int i = (2*nonce_size + 10); i < read_bytes; i++)
		encrypted_message.push_back(recv_buff[i]);
	
	/******verification****/
	std::string message_to_verify = received_nonceRA + received_nonceRB + "serverA   "/*+ received_B + text2*/;
	DEBUG_ONLY(std::cout<<"Message to verify : "<<message_to_verify<<std::endl);
	usleep(timeInterval);
	bool auth;
	int result = RSAVerifySignature(public_key, (unsigned char*)encrypted_message.c_str(), encrypted_message.length(), message_to_verify.c_str(), message_to_verify.length(), &auth);
	DASSERT(received_A == "serverA   ", "NAMES OF SERVER IDENTFIERS ARE DIFFERENT");
	DASSERT(received_nonceRB == nonceRB, "NONCE RECEIVED VALUE AND CLIENT VALUE ARE DIFFERENT");
	DEBUG_ONLY(std::cout<<"RECEIVED NONCE IS EQUAL TO THE ORIGINAL"<<std::endl);
	usleep(timeInterval);

	
	
	DEBUG_ONLY(std::cout<<"The result of comparision : "<<(result && auth)<<std::endl);
	if((result&&auth) == 0)
	{
		std::cout<<"SIGNATURES ARE NOT IDENTICAL"<<std::endl;
		abort();
	}
	usleep(timeInterval);
	DEBUG_ONLY(std::cout<<"SERVER VERIFICATION HAS PASSED"<<std::endl);
	
	/****generate sign and unsigned message***/
	std::string client_answer_sign = nonceRB + received_nonceRA + B/* + text4*/;
	DEBUG_ONLY(std::cout<<"Client signed answer : "<<client_answer_sign<<std::endl);
	usleep(timeInterval);
	
	std::string client_answer_nosign = nonceRB + received_nonceRA + B/* + "end       "*/;
	DEBUG_ONLY(std::cout<<"Client not signed answer : "<<client_answer_nosign<<std::endl);
	usleep(timeInterval);
	
	unsigned char* enc_msg;
	size_t enc_length;
	RSASign(private_key, (unsigned char*)client_answer_sign.c_str(), client_answer_sign.length(), &enc_msg, &enc_length);
	DEBUG_ONLY(std::cout<<"Encrypted message length : "<< enc_length<<std::endl);
	usleep(timeInterval);
	
	copyValue(enc_msg, enc_length, client_answer_nosign);
	written_bytes = write(socket, client_answer_nosign.c_str(), client_answer_nosign.length());
	DEBUG_ONLY(std::cout<<"Written message(second client message) : "<<client_answer_nosign<<std::endl);
	usleep(timeInterval);
	DEBUG_ONLY(std::cout<<"Written size is(second client message) : "<<client_answer_nosign.length()<<std::endl);
	usleep(timeInterval);
}

int main(int argc, char** argv) {
	srand (time(NULL));
	clientId = 1;
	struct sockaddr_in stSockAddr;
	int i32SocketFD = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	char sendBuff[1025];
	assert(i32SocketFD != -1);

	RSA* private_key = readPrivateKey();
	RSA* public_key = readPublicKey();
	RSA* ownPublickKey = readOwnPublickKey();
	
	std::string random;
	generateRandomNumber(random);
	std::string message = generateMessageOne(random);
	
	process_connection(i32SocketFD, stSockAddr, message, public_key, private_key, ownPublickKey);
	fflush(stdout);
	return 0;
}