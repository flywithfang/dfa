
// use boost bind placeholders for now
#include <locale.h>
#include <thread>
#include <iostream>
#include <sstream>
#include <fstream>
#include <ctype.h>

#include "include_base_utils.h"
#include "console_handler.h"
#include "common/i18n.h"
#include "common/command_line.h"
#include "common/util.h"
#include "common/dns_utils.h"
#include "common/base58.h"
#include "common/scoped_message_writer.h"
#include "cryptonote_protocol/cryptonote_protocol_handler.h"
#include "cryptonote_basic/cryptonote_format_utils.h"
#include "storages/http_abstract_invoke.h"
#include "rpc/core_rpc_server_commands_defs.h"

#include "crypto/crypto.h"  // for crypto::secret_key definition
#include "mnemonics/electrum-words.h"
#include "rapidjson/document.h"
#include "common/json_util.h"
#include "ringct/rctSigs.h"
#include "version.h"
#include "string_tools.h"
#include <stdexcept>
#include <filesystem>

#include "cryptonote_core/tx_pool.h"
#include "cryptonote_core/cryptonote_core.h"
#include "blockchain_db/blockchain_db.h"

#include "blockchain_db/lmdb/db_lmdb.h"

#include "mnemonics/electrum-words.h"

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

using namespace std;
using namespace epee;
using namespace cryptonote;
using namespace crypto;

Blockchain* chain;
BlockchainDB* db ;

   secret_key a,b;

template< class T>
    inline std::ostream &operator <<(std::ostream &o, const std::vector<T> &v) {
    int index=0;
    for(auto s:v){
      o<<std::to_string(index)<<":";
      epee::to_hex::formatted(o, epee::as_byte_span(s)); 
      o<<std::endl;
      ++index;
  }
  return o;
  }

class print_extra_visitor : public boost::static_visitor<void>
{
public:
     
     public_key tx_key;
    void operator()(const tx_extra_nonce & e) 
    {
        std::cout<<"extra nonce "<<endl<<e.nonce.size()<<","<<e.nonce<<std::endl;
    }
 
};

tuple<public_key> print_extra(const std::vector<uint8_t> & tx_extra){


    std::string extra_str(reinterpret_cast<const char*>(tx_extra.data()), tx_extra.size());
    std::istringstream iss(extra_str);
    binary_archive<false> ar(iss);

   cout<<boost::is_integral<tx_extra_field>::type()<<endl;
   cout<< is_blob_type<tx_extra_field>::type()<<endl;
   cout<< is_basic_type<tx_extra_field>::type()<<endl;
    print_extra_visitor v;
        while (!iss.eof())
        {
          tx_extra_field field;
          //bool r = ::do_serialize(ar, field);
          bool r = ::serializer<binary_archive<false>,tx_extra_field>::serialize(ar,field);
          if(!r) break;
          if(iss.fail()) break;
           boost::apply_visitor( v, field);
           cout<<"read extra"<<endl;
         }
         cout<<"read over"<<endl;
    return std::make_tuple(v.tx_key);
}
template <class T>
string to_json_string(const T & tx){
   std::ostringstream ost;
  json_archive<true> a(ost);
  ::serialization::serialize(a,const_cast<T&>(tx));
  auto js= ost.str();
  return js;
}
rct::keyV print_in(const transaction & tx){
   auto index=0;
  rct::rctSig  rct = tx.rct_signatures;
  const auto &  CC = rct.get_pseudo_outs();
   for(auto tin : tx.vin){

    txin_to_key tk = boost::get<txin_to_key>(tin);
    cout<<"vin "<<index++<<endl;
    uint64_t last=0;
      for(auto of : tk.key_offsets){
        auto r_o = of;
        if(last){
          r_o =  last+of;
        }
        last = r_o;
        output_data_t out = db->get_output_key(r_o,true);
        cout<<"  "<<out.height<<",o-k "<<out.otk<<","<<out.unlock_time<<",C1="<<out.commitment<<","<<endl;
      }
      const bool spent=db->has_key_image(tk.k_image);
    cout<<"key_image "<<tk.k_image<<",spent:"<<spent<<endl;
    const auto C=CC[index];
    cout<<"C2="<<C<<endl;

   }
   return CC;
}

 static void xor8(rct::key &v, const rct::key &k)
    {
        for (int i = 0; i < 8; ++i)
            v.bytes[i] ^= k.bytes[i];
    }
rct::keyV print_out(const public_key & tx_key, const transaction & tx){

     ///Ra=rGa
    rct::keyV out;
   key_derivation kd1;
   crypto::generate_key_derivation(tx_key,a,kd1);

   auto t=0;
     rct::rctSig  rct = tx.rct_signatures;
    cout<<"rct "<<to_string(rct.type)<<endl;
     auto & ecdhs = rct.ecdhInfo;
     const auto outPk=rct.outPk;
    public_key B;
    crypto::secret_key_to_public_key(b,B);
   for(auto o : tx.vout){

    txout_to_key tk = boost::get<txout_to_key>(o.target);
    cout<<"out one-time-key  "<<t<<","<<tk.key<<",";
     auto & ecdh= ecdhs[t];
      secret_key s;
      crypto::derivation_to_scalar(kd1,t,s);
      rct::key shared_seret =rct::sk2rct(s);
   //  rct::ecdhDecode(ecdh,shared_seret,true);
       const auto noise = rct::genCommitmentMask(shared_seret);

     uint64_t a= rct::ecdhDecode(ecdh.amount,shared_seret);
     //auto C = rct::addKeys2()
     cout<<"amount="<<print_money(a)<<endl;
     ///H(Ra,i)G+B
     auto [r,my_one_time_key]=crypto::derive_public_key(kd1,t,B);
     cout<< (my_one_time_key==tk.key ? "MY MONEY!!!!" : "OTHER MONEY")<<endl;
     const auto H=rct::H;
     rct::key xGbH;
      rct::key a2;
      rct::d2h(a2,a);
     rct::addKeys2(xGbH,noise,a2,H);
     cout<<"outC="<<xGbH<<endl;
     const auto outC=outPk[t].commitment;
     cout<<"outC="<<outC<<endl;
     out.push_back(outC);
    ++t;
   }
   return out;
}
void print_tx(Blockchain* chain,const string& _tx_hash, bool json){

  cout<<"print_tx "<<_tx_hash<<endl;
  crypto::hash tx_hash;
  string_tools::hex_to_pod(_tx_hash,tx_hash);
  blobdata blob;
  auto r = db->get_tx_blob(tx_hash,blob);
  if(!r) throw new runtime_error("get_tx");
  cout<<"tran size "<<blob.size()<<endl;
  if(json){
  transaction tx;
  if (!parse_and_validate_tx_from_blob(blob, tx))
    throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");
   auto js=to_json_string(tx);
   cout<<js<<endl;
   auto [tx_key] = print_extra(tx.extra);
   cout<<"tx_key "<<tx_key<<endl;

    print_in(tx);
    print_out(tx_key,tx);
  
}
else{
  cout<<blob<<endl;
}

}
bool initChain(){

  LOG_PRINT_L0("Initializing source blockchain (BlockchainDB)");


  db = new_db();
  if (db == NULL)
  {
    LOG_ERROR("Failed to initialize a database");
    throw std::runtime_error("Failed to initialize a database");
  }
  LOG_PRINT_L0("database: LMDB");

  filesystem::path folder("/monerod");
  folder /= db->get_db_name();
  const std::string filename = folder.string();

  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");
  try
  {
    db->open(filename, DBF_RDONLY);
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return false;
  }

  tx_memory_pool m_mempool(*chain);
  chain = new Blockchain(m_mempool);
  auto opt_testnet=false, opt_stagenet=false;
  auto r = chain->init(db, opt_testnet ? cryptonote::TESTNET : opt_stagenet ? cryptonote::STAGENET : cryptonote::MAINNET);
  if(!r){
    throw new runtime_error("fail to init chain");
  }
  const auto c_t = db->get_tx_count() ;
  cout<<"total transaction "<<c_t<<endl;
  const auto db_size=db->get_database_size();
  cout<<"db size"<<db_size<<endl;

  return true;
}

void check_kimage(const string & ki){
 crypto::key_image  k_image;
  string_tools::hex_to_pod(ki,k_image);
   const bool spent=db->has_key_image(k_image);
    cout<<"key_image "<<k_image<<",spent:"<<spent<<endl;
}
void construct_genesis_block(){

//    const auto sk="533b55261db0bd3092b19c6ab60aeddb546ed6261757d1fc9d80c6198374a806";
    const auto seed="rodent wobbly bubble satin among ecstatic desk richly bypass usage listen guest bimonthly narrate renting idols reef quote value leopard nucleus cafe hookup initiate desk";
    const auto  [recover_key,lang]= ElectrumWords::words_to_bytes(seed);
    account_base acc;
    acc.generate(recover_key,true);
    const auto spend_key = acc.get_keys().m_spend_secret_key;
    cout<<string_tools::pod_to_hex(spend_key)<<endl;
    {
        const auto seed2 = ElectrumWords::bytes_to_words(spend_key);
        if(!seed2) throw runtime_error("bad seed");
        cout<<seed2.value().data()<<endl;
    }

    auto addr = acc.get_address();
    const auto addr_str = cryptonote::get_account_address_as_str(cryptonote::network_type::MAINNET,addr);
    cout<<"addr:"<<addr_str<<endl;
    auto [r,tx]=cryptonote::construct_miner_tx(0,0,0,0,0,addr);
    if(!r) throw std::runtime_error("generate tx error");

    const auto s = to_json_string(tx);
    cout<<s<<endl;
    blobdata bd;
    t_serializable_object_to_blob(tx,bd);
    const auto hx=string_tools::buff_to_hex_nodelimer(bd);
    cout<<hx<<endl;
 //genesis block
    block bl {};

    bl.miner_tx = tx;
    bl.major_version = CURRENT_BLOCK_MAJOR_VERSION;
    bl.minor_version = CURRENT_BLOCK_MINOR_VERSION;
    bl.timestamp = 0;
    bl.nonce = 0;
    miner::find_nonce_for_given_block(nullptr,bl, 1, 0);
    bl.invalidate_hashes();
    cout<<to_json_string(bl)<<endl;

    const auto blob = get_block_hashing_blob(bl);
    cout<<"bl header "<<string_tools::buff_to_hex_nodelimer(blob);
}
void cal_block_hash(const string & hex){
    
    blobdata bd;
    auto r =from_hex::to_string(bd,hex);
    cout<<bd.size()<<endl;
    if(!r) throw runtime_error("bad hex");
    
    
   const block bl = cryptonote::parse_and_validate_block_from_blob(bd);
   crypto::hash hash=get_block_hash(bl);
    cout<<"hash "<<hash<<endl;
    cout<<to_json_string(bl)<<endl;
}
int main(int argc, char const * argv[]){

  std::vector<std::string> args(argv, argv+argc);
  for(auto p:args){
   cout<<p<<endl; 
  }
 

  auto cmd=args[1];
  if(cmd=="check_image"){
    const auto kimage=args[2];
     initChain();
    check_kimage(kimage);
    return 0;
  }
  else if(cmd=="genesis"){
    construct_genesis_block();
    return 0;
  }
  else if(cmd=="block_hash"){
    cal_block_hash(args[2]); return 0;
  }

   initChain();
  auto tx_hash=args[2];
  auto json= argc<4 || args[3]=="json";


   string_tools::hex_to_pod("b60580c073a2679186fd99bf2fb75c86b550e39ef39f376711b7a3a2eae90a05",a);
   string_tools::hex_to_pod("1520ee4190e2a54832387ae398e7b15f36e5d11c82089bbeaf8619a7ea07f708",b);
   cout<<"a "<<a<<endl;
   cout<<"b "<<b<<endl;

try{

  
  ((BlockchainLMDB*)db)->print_databases();
  print_tx(chain,tx_hash,json);

}
catch(std::runtime_error& e)
{
   cout << "runtime error"<<e.what() << "\n";
}
catch(std::exception & ex){
  cerr<<"exception"<<ex.what()<<endl;
}
catch(...){
  cerr<<"somthing happend!"<<endl;
}

  return 0;
}