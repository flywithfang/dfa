
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
#include "serialization/binary_utils.h"

#ifdef HAVE_READLINE
#include "readline_buffer.h"
#endif

using namespace std;
using namespace epee;
using namespace cryptonote;
using namespace crypto;

struct Core{
tx_memory_pool mempool;
Blockchain chain ;
Core():mempool(chain),chain(mempool){}
};
Core m_core;
BlockchainDB* db ;
account_base acc;
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
        output_data_t out = db->get_output_key(r_o);
        cout<<"  "<<out.height<<",o-k "<<out.otk<<","<<out.unlock_time<<",C1="<<out.commitment<<","<<endl;
      }
      const bool spent=db->has_key_image(tk.k_image);
    cout<<"key_image "<<tk.k_image<<",spent:"<<spent<<endl;
    const auto C=CC[index];
    cout<<"C2="<<C<<endl;

   }
   return CC;
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
     const auto outCommitments=rct.outCommitments;
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
     const auto outC=outCommitments[t].commitment;
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
  if (!parse_tx_from_blob(blob, tx))
    throw DB_ERROR("Failed to parse transaction from blob retrieved from the db");
   auto js=to_json_string(tx);
   cout<<js<<endl;
   cout<<"tx_key "<<tx.tx_pub_key<<endl;

    print_in(tx);
    print_out(tx.tx_pub_key,tx);
  
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

  filesystem::path folder("/home/winston/.dfa");
  folder /= db->get_db_name();
  const std::string filename = folder.string();

  LOG_PRINT_L0("Loading blockchain from folder " << filename << " ...");
  try
  {
    db->open(filename, DBF_RDONLY);//
  }
  catch (const std::exception& e)
  {
    LOG_PRINT_L0("Error opening database: " << e.what());
    return false;
  }

  auto opt_testnet=false, opt_stagenet=false;
  auto r = m_core.chain.init(db, opt_testnet ? cryptonote::TESTNET : opt_stagenet ? cryptonote::STAGENET : cryptonote::MAINNET);
  if(!r){
    throw new runtime_error("fail to init chain");
  }
  const auto c_t = db->get_tx_count() ;
  cout<<"total transaction "<<c_t<<endl;
  const auto db_size=db->get_database_size();
  cout<<"db size"<<db_size<<endl;

  return true;
}
void init_account(){
   const auto  sk="b518b244a2f17b9e6fdae3b21b8f80e4ceb6f5e367cb892b660a0bd5cc2a6e0a";
    crypto::secret_key recover_key;
   ::serialization::parse_binary(string_tools::parse_hexstr_to_binbuff(sk),recover_key);
    acc.generate(recover_key,true);

}

void check_kimage(const string & ki){
 crypto::key_image  k_image;
  string_tools::hex_to_pod(ki,k_image);
   const bool spent=db->has_key_image(k_image);
    cout<<"key_image "<<k_image<<",spent:"<<spent<<endl;
}
void construct_genesis_block(){

    const auto spend_key = acc.get_keys().m_spend_secret_key;
    cout<<"b "<<string_tools::pod_to_hex(spend_key)<<endl;
    auto addr = acc.get_address();
    const auto addr_str = cryptonote::get_account_address_as_str(cryptonote::network_type::MAINNET,addr);
    cout<<"addr:"<<addr_str<<endl;
    auto [r,tx]=cryptonote::construct_miner_tx(0,0,addr);
    if(!r) throw std::runtime_error("generate tx error");

    const auto s = to_json_string(tx);
    cout<<s<<endl;
    blobdata bd;
    t_serializable_object_to_blob(tx,bd);
    const auto hx=string_tools::buff_to_hex_nodelimer(bd);
    cout<<"GENESIS_TX "<<hx<<endl;
 //genesis block
    block bl =   make_genesis_block(hx,0);
  
    cout<<to_json_string(bl)<<endl;

    const auto blob = get_block_hashing_blob(bl);
    cout<<"bl header "<<string_tools::buff_to_hex_nodelimer(blob);
}
void cal_block_hash(const string & hex){
    
    blobdata bd;
    auto r =from_hex::to_string(bd,hex);
    cout<<bd.size()<<endl;
    if(!r) throw runtime_error("bad hex");
    
    
   const block bl = cryptonote::parse_block_from_blob(bd);
   crypto::hash hash=get_block_hash(bl);
    cout<<"hash "<<hash<<endl;
    cout<<to_json_string(bl)<<endl;
}
void check_block(const string &hex){

  const auto buf = string_tools::parse_hexstr_to_binbuff(hex);
  const auto b = cryptonote::parse_block_from_blob(buf);
    cout<<to_json_string(b)<<endl;
crypto::hash h;
    calculate_block_hash(b,h);
    cout<<"block hash"<<h<<endl;
}
void test_block_template(const string &arg){

  const auto addr = acc.get_address();
  blobdata b(17,0);
  const auto bt=m_core.create_block_template(nullptr,addr,b);
  const auto & bd= t_serializable_object_to_blob(bt.b);
  cout<<string_tools::buff_to_hex_nodelimer(bd);
  const auto b2 = parse_block_from_blob(bd);
   cout<<to_json_string(b2)<<endl;

}
int main(int argc, char const * argv[]){

  std::vector<std::string> args(argv, argv+argc);
  for(auto p:args){
   cout<<p<<endl; 
  }
 mlog_set_log_level(6);

 init_account();
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
  else if(cmd=="check_block"){
    check_block(args[2]); return 0;
  }

   initChain();
  

try{
   ((BlockchainLMDB*)db)->print_databases();
   std::cout<<cmd<<std::endl;
  if(cmd=="test_b_template"){
    test_block_template(args[2]); return 0;
  }

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