/*
 * Code obtained from: http://marko-editor.com/articles/cryptopp_sign_string/
 * @autor: Michael Munzert
 * 
 * slightly adapted by: dnatividade
 */

#include "crypto.h"
#include <iostream>
#include <string>

using std::cout;
using std::endl;

int main(int, char **) {
  auto keys = RsaGenerateHexKeyPair(KEYSIZE);
  cout << "Private key: " << endl << keys.privateKey << "\n" << endl;
  cout << "Public key: " << endl << keys.publicKey << "\n" << endl;

  string message("secret message");
  cout << "Message:" << endl;
  cout << message << "\n" << endl;

  // generate a signature for the message
  auto signature(RsaSignString(keys.privateKey, message));
  cout << "Signature:" << endl;
  cout << signature << "\n" << endl;

  // verify signature against public key
  if (RsaVerifyString(keys.publicKey, message, signature)) {
    cout << "Signatue valid." << endl;
  } else {
    cout << "Signatue invalid." << endl;
  }
}
