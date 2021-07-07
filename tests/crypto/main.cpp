#include <cstddef>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include "warnings.h"
#include "misc_log_ex.h"
#include "crypto/crypto.h"
#include "crypto/hash.h"
#include "crypto-tests.h"
#include "../io.h"
#include "hex.h"

using namespace std;
using namespace crypto;
typedef crypto::hash chash;

bool operator !=(const ec_scalar &a, const ec_scalar &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_scalar));
}

bool operator !=(const ec_point &a, const ec_point &b) {
  return 0 != memcmp(&a, &b, sizeof(ec_point));
}

bool operator !=(const key_derivation &a, const key_derivation &b) {
  return 0 != memcmp(&a, &b, sizeof(key_derivation));
}

DISABLE_GCC_WARNING(maybe-uninitialized)

int main(int argc, char *argv[]) {
  TRY_ENTRY();
  fstream input;
  string cmd;
  size_t test = 0;
  bool error = false;
  setup_random();
  if (argc != 2) {
    cerr << "invalid arguments" << endl;
    return 1;
  }
  input.open(argv[1], ios_base::in);
  for (;;) {
    ++test;
    input.exceptions(ios_base::badbit);
    if (!(input >> cmd)) {
      break;
    }
     cout<<cmd<<endl;
    input.exceptions(ios_base::badbit | ios_base::failbit | ios_base::eofbit);
    if (cmd == "check_scalar") {
      ec_scalar scalar;
      bool expected, actual;
      get(input, scalar, expected);
      actual = check_scalar(scalar);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "random_scalar") {
      ec_scalar expected, actual;
      get(input, expected);
      std::cout<<expected<<endl;
      random_scalar(actual);
      std::cout<<"actural "<< actual<<endl;
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "hash_to_scalar") {
      vector<char> data;
      ec_scalar expected, actual;
      get(input, data, expected);
      crypto::hash_to_scalar(data.data(), data.size(), actual);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "generate_keys") {
      public_key expected1, actual1;
      secret_key expected2, actual2;
      get(input, expected1, expected2);
      generate_keys(actual1, actual2);
      if (expected1 != actual1 || expected2 != actual2) {
        goto error;
      }
    } else if (cmd == "check_key") {
      public_key key;
      bool expected, actual;
      get(input, key, expected);
      actual = check_key(key);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "secret_key_to_public_key") {
      secret_key sec;
      bool expected1;
      public_key expected2, pub2;
      get(input, sec, expected1);
      if (expected1) {
        get(input, expected2);
      }
      cout<<"sec"<<sec<<endl;
      
      auto valid = secret_key_to_public_key(sec, pub2);
      if (expected1 != valid || (expected1 && expected2 != pub2)) {
        goto error;
      }
      cout<<"pub"<<pub2<<endl;
    } else if (cmd == "generate_key_derivation") {
      public_key key1;
      secret_key key2;
      bool expected1, actual1;
      key_derivation expected2, actual2;
      get(input, key1, key2, expected1);
      if (expected1) {
        get(input, expected2);
      }
      actual1 = generate_key_derivation(key1, key2, actual2);
      if (expected1 != actual1 || (expected1 && expected2 != actual2)) {
        goto error;
      }
    } else if (cmd == "derive_public_key") {
      key_derivation derivation;
      size_t output_index;
      public_key base;
      bool expected1, actual1;
      public_key expected2, actual2;
      get(input, derivation, output_index, base, expected1);
      if (expected1) {
        get(input, expected2);
      }
      actual1 = derive_public_key(derivation, output_index, base, actual2);
      if (expected1 != actual1 || (expected1 && expected2 != actual2)) {
        goto error;
      }
    } else if (cmd == "derive_secret_key") {
      key_derivation derivation;
      size_t output_index;
      secret_key base;
      secret_key expected, actual;
      get(input, derivation, output_index, base, expected);
      derive_secret_key(derivation, output_index, base, actual);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "generate_signature") {

      chash prefix_hash;
      public_key pub;
      secret_key sec;
      signature sig1, sig2;
      get(input, prefix_hash, pub, sec, sig1);
      cout<<"sec"<<sec<<endl;
      cout<<"pub"<<pub<<endl;
      public_key p2;
      secret_key_to_public_key(sec,p2);

      cout<<"pub"<<p2<<endl;
      generate_signature(prefix_hash, p2, sec, sig2);
      cout<<"sig1"<<sig1<<endl;
      cout<<"sig2"<<sig2<<endl;
      if (sig1 != sig2) {
        goto error;
      }
    } else if (cmd == "check_signature") {
      chash prefix_hash;
      public_key pub;
      signature sig;
      bool expected, actual;
      get(input, prefix_hash, pub, sig, expected);
      actual = check_signature(prefix_hash, pub, sig);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "hash_to_point") {
      chash h;
      ec_point expected, actual;
      get(input, h, expected);
      hash_to_point(h, actual);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "hash_to_ec") {
      public_key key;
      ec_point expected, actual;
      get(input, key, expected);
      hash_to_ec(key, actual);
      if (expected != actual) {
        goto error;
      }
    } else if (cmd == "generate_key_image") {
      public_key pub;
      secret_key sec;
      key_image ki1, ki2;
      get(input, pub, sec, ki1);
      public_key p2;
      crypto::secret_key_to_public_key(sec,p2);
      cout<<"p1"<<pub<<endl;
      cout<<"p2"<<p2<<endl;
      generate_key_image(pub, sec, ki2);
      if (ki1 != ki2) {
        goto error;
      }
    } else if (cmd == "generate_ring_signature") {
      crypto::hash prefix_hash;
      key_image image;
      vector<public_key> vpubs;
      vector<const public_key *> pubs;
      size_t pubs_count;
      secret_key sec;
      size_t sec_index;
      vector<signature> sigs1, sigs2;
      size_t i;
      get(input, prefix_hash, image, pubs_count);
      vpubs.resize(pubs_count);
      pubs.resize(pubs_count);
      for (i = 0; i < pubs_count; i++) {
        get(input, vpubs[i]);
        pubs[i] = &vpubs[i];
      }
      get(input, sec, sec_index);
      sigs1.resize(pubs_count);
      getvar(input, pubs_count * sizeof(signature), sigs1.data());
      sigs2.resize(pubs_count);
      generate_ring_signature(prefix_hash, image, pubs.data(), pubs_count, sec, sec_index, sigs2.data());
      cout<<"sigs1"<<sigs1<<endl;
      cout<<"sigs2"<<sigs2<<endl;
      if (sigs1 != sigs2) {
        goto error;
      }

    } else if (cmd == "check_ring_signature") {
      chash prefix_hash;
      key_image image;
      vector<public_key> vpubs;
      vector<const public_key *> pubs;
      size_t pubs_count;
      vector<signature> sigs;
      bool expected, actual;
      size_t i;
      get(input, prefix_hash, image, pubs_count);
      cout<<"image"<<image<<endl;
      cout<<"p_count"<<pubs_count<<endl;
      vpubs.resize(pubs_count);
      pubs.resize(pubs_count);
      for (i = 0; i < pubs_count; i++) {
        get(input, vpubs[i]);
        cout<<vpubs[i]<<endl;
        pubs[i] = &vpubs[i];
      }
      sigs.resize(pubs_count);
      getvar(input, pubs_count * sizeof(signature), sigs.data());
      cout<<sigs<<endl;
      get(input, expected);
      cout<<expected<<endl;
      actual = check_ring_signature(prefix_hash, image, pubs.data(), pubs_count, sigs.data());
      cout<<actual<<expected<<endl;
      if (expected != actual) {
        goto error;
      }
    } else {
      throw ios_base::failure("Unknown function: " + cmd);
    }
    continue;
error:
    cerr << "Wrong result on test " << test << endl;
    error = true;
  }
  return error ? 1 : 0;
  CATCH_ENTRY_L0("main", 1);
}
