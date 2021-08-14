
bool __check_own(const output_data_t & ot){


}
std::vector<transfer_details> wallet_sync(uint64_t start_height,const secret_key & a,const public_key & B){

std::vector<transfer_details> v;
 Blockchain bc;
 //B+H(kA,i)G=otk
 bc.for_all_outputs(start_height,[&](auto oid,const auto & ot){
 	const auto & otk = ot.otk;
 	const auto & tx_pub_key= ot.tx_pub_key;
 	 crypto::key_derivation kA;
    bool r = crypto::generate_key_derivation(tx_pub_key, a, kA);
    if(!r)
   	 throw_and_log( "Failed to generate key derivation");
    crypto::public_key otk2;
    r = crypto::derive_public_key(kA, ot.local_index, B, otk2);
    if (otk==otk2){
    	MDEBUG("found own trans "<<ot.tx_hash);
    	transfer_details td;
    	td.otk = otk;
    	td.m_block_height = ot.height;
    	td.m_txid = ot.tx_hash;
    	td.m_internal_output_index=ot.local_index;
    	td.m_global_output_index = oid;
    }
    return true;
 });

return v;
}