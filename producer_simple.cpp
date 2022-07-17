/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2013-2022 Regents of the University of California.
 *
 * This file is part of ndn-cxx library (NDN C++ library with eXperimental eXtensions).
 *
 * ndn-cxx library is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later version.
 *
 * ndn-cxx library is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received copies of the GNU General Public License and GNU Lesser
 * General Public License along with ndn-cxx, e.g., in COPYING.md file.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndn-cxx authors and contributors.
 */

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>
#include <sstream>

#include <nlohmann/json.hpp>

// for convenience
using json = nlohmann::json;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Producer
{
public:
  void
  run()
  {
    m_face.setInterestFilter("/example/test/function",
                             std::bind(&Producer::onInterest, this, _1, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));

    auto cert = m_keyChain.getPib().getDefaultIdentity().getDefaultKey().getDefaultCertificate();
    m_certServeHandle = m_face.setInterestFilter(security::extractIdentityFromCertName(cert.getName()),
                             [this, cert] (auto&&...) {
                               m_face.put(cert);
                             },
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
    m_face.processEvents();
  }

private:
  void
  onInterest(const InterestFilter&, const Interest& interest)
  {     
    if( interest.hasApplicationParameters() ) {

      //std::cout << ">> I: " << interest << std::endl;
      //std::cout << " \n app params: " << std::endl;

      Block appParams = interest.getApplicationParameters();
      appParams.parse();

      int type = appParams.elements()[0].type();   

      //Block content((uint32_t)500);
      const unsigned char* buf_arg;
      int args_length;
      std::string consumer_prefix = "";
      std::string id="";
      
      switch(type){
        case 130:{
          std::cout << "interest type 130 " << std::endl;

          Block in = appParams.get(type);
          in.parse();
          for ( auto e: in.elements() )
          { 
            //std::cout << "element inside app params block : " << e << std::endl;
            if (e.type() == 200){

              Block data = in.get(200);
              data.parse();

              for(auto e2 : data.elements() )
              {
                if(e2.type() ==300 ){
                  std::cout << "type 300 found: buffer" <<std::endl;
                  Block buffer = data.get(300);
                  // buffer.parse();

                  buf_arg = reinterpret_cast<const unsigned char*>(buffer.value());
                  
                }
                else if(e2.type() ==301 ){
                  std::cout << "type 301 found: length" <<std::endl;
                  Block length = data.get(301);
                  //length.parse();
                  const char* aux = reinterpret_cast<const char*>(length.value());
                  args_length = *reinterpret_cast<const int*>(aux);
                  //auto v = std::vector< unsigned char>(aux, aux + length.value_size());
                  
                  //for(auto a : v) {std::cout << (int)a << std::endl;}
                  //std::string value(v.begin(), v.end());
                  //std::cout << "value: " << value << std::endl;
                  //args_length = stoi(value);
                  std::cout << "length = " << args_length << std::endl;
                }
                else{
                  std::cout << "unknown type" << std::endl;
                }
              }
            }
          }
          Block content((uint32_t)500);
          content.insert(content.elements_end() , Sum(buf_arg, args_length));
          content.encode(); 

          sendData(interest.getName(),content);

          break;
        }
          
    
        case 131: {

          std::cout << "interest type 131 " << std::endl;
          Block in = appParams.get(type);
          in.parse();
          for ( auto e: in.elements() )
          { 
            //std::cout << "element inside app params block : " << e << std::endl;
            if (e.type() == 302){ 
              std::cout << "type 302 found: prefix" <<std::endl;
              Block prefix = in.get(302);
              // buffer.parse();
              std::string s =std::string(reinterpret_cast<const char*>(prefix.value()), prefix.value_size());
              consumer_prefix = s;
              std::cout << "prefix : "<< consumer_prefix << std::endl;
            }
            else if (e.type() == 303){ 
              std::cout << "type 303 found: id" <<std::endl;
              Block block_id = in.get(303);
              // buffer.parse();
              std::string s =std::string(reinterpret_cast<const char*>(block_id.value()), block_id.value_size());
              id = s;
              std::cout << "id : "<< s << std::endl;

            }
          }

          auto a_id = Buffer(id.data(), id.size());
          auto b_id = std::make_shared<Buffer>(a_id);
          Block id_block((uint32_t)303, b_id);
          id_block.encode();

          Block content((uint32_t)500);
          content.insert(content.elements_end() , id_block);
          content.encode(); 

          sendData(interest.getName(),content);

          fetchInput(consumer_prefix,id);

          std::cout << "after fecth input" << std::endl;
          break;
        }
       case 135: {
          Block in = appParams.get(type);
          in.parse();
          for ( auto e: in.elements())
          {
            if (e.type()==303){
              std::cout << "type 303 found: id" <<std::endl;
              Block block_id = in.get(303);
              id =std::string(reinterpret_cast<const char*>(block_id.value()), block_id.value_size());
            }
          }
          if (id != ""){
            auto a_id = Buffer(id.data(), id.size());
            auto b_id = std::make_shared<Buffer>(a_id);
            Block id_block((uint32_t)303, b_id);
            id_block.encode();

            Block content((uint32_t)510);
            content.insert(content.elements_end() , id_block);
            content.insert(content.elements_end() , results[id]);
            content.encode(); 

            sendData(interest.getName(),content);
          }
          break;
        }
        default:{
         json resp;
         resp["error"]="unknown TLV type";
         //content=resp.dump();
         break;
       }
      }
    
    }
  }

    //static const std::string content("Hello, world!");

    // Create Data packet
    

    // in order for the consumer application to be able to validate the packet, you need to setup
    // the following keys:
    // 1. Generate example trust anchor
    //
    //         ndnsec key-gen /example
    //         ndnsec cert-dump -i /example > example-trust-anchor.cert
    //
    // 2. Create a key for the producer and sign it with the example trust anchor
    //
    //         ndnsec key-gen /example/testApp
    //         ndnsec sign-req /example/testApp | ndnsec cert-gen -s /example -i example | ndnsec cert-install -

    // Sign Data packet with default identity
    
  

  std::string
  fetchInput(std::string prefix, std::string id){
    auto a2 = Buffer(id.data(),id.size());
    auto m2 = std::make_shared<Buffer>(a2);

    Block id_block((uint32_t)303,m2);
    id_block.encode();

    sendInterest(prefix, id_block, 132);

  }

  void
  onData(const Interest&, const Data& data, std::string prefix)
  {
    std::cout << "ON DATA" << std::endl;
    Block response = data.getContent();
    response.parse();
    int type = response.elements()[0].type();   
    std::string id;
    const unsigned char* buf_arg;
    int args_length=0;
    switch(type){
      case 520:{
        std::cout << "data type 520 " << std::endl;

        Block in = response.get(type);
        in.parse();
        for ( auto e: in.elements())
        {
          if(e.type()==303){
            std::cout<< "saving id" << std::endl;
            Block block_id = in.get(303);
              // buffer.parse();
              id =std::string(reinterpret_cast<const char*>(block_id.value()), block_id.value_size());
          }
          if(e.type()==200){
            std::cout<< "fetching input" << std::endl;
            Block data_block = in.get(200);
            data_block.parse();

            for(auto e2 : data_block.elements() )
            {
              if(e2.type() ==300 ){
                std::cout << "type 300 found: buffer" <<std::endl;
                Block buffer = data_block.get(300);
                buf_arg = reinterpret_cast<const unsigned char*>(buffer.value());
              }
              if(e2.type() ==301 ){
                std::cout << "type 301 found: length" <<std::endl;
                Block length = data_block.get(301);
                //length.parse();
                const char* aux = reinterpret_cast<const char*>(length.value());
                args_length = *reinterpret_cast<const int*>(aux);
                std::cout << "length = " << args_length << std::endl;
              } 
            }
          }
        }
        if(args_length != 0){
          results[id] = Sum(buf_arg, args_length);

          auto a2 = Buffer(id.data(),id.size());
          auto m2 = std::make_shared<Buffer>(a2);

          Block id_block((uint32_t)303,m2);
          id_block.encode();
          sendInterest(prefix, id_block, 133);
        } 

        break;
      }
      case 521:{
        std::cout << "waiting to consumer get output.. "  << std::endl;
        break;
      }

      default:
      
        break;
      


    }

  }

  void
  onNack(const Interest&, const lp::Nack& nack) const
  {
    std::cout << "Received Nack with reason " << nack.getReason() << std::endl;
  }

  void
  onTimeout(const Interest& interest) const
  {
    std::cout << "Timeout for " << interest << std::endl;
  }

  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

  Block
  Sum(const unsigned char* bytes, size_t size){

    //auto v = std::vector< unsigned char>(vector, vector + size);

    std::vector<unsigned char> byteVec(bytes, bytes + sizeof(float) * size);

    unsigned char* bytes2 = &(byteVec[0]);    // point to beginning of memory
    float* floatArray = reinterpret_cast<float*>(bytes2);

    float sum = 0;
    for (int i = 0; i < size; i++){
        std::cout << "after:"<< floatArray[i] << std::endl; 
        sum += floatArray[i];
    }

    /*int sum=0;
    for(auto i : v){
      std::cout << std::to_string(i) << std::endl;
      sum+= (int) i;
    
    }*/

    std::cout << "return from Sum(arg) : " << sum << std::endl;
    std::string result = std::to_string(sum);

    auto a = Buffer(result.data(),result.size());
    auto b = std::make_shared<Buffer>(a);
    Block res((uint32_t)501, b);
    res.encode();
    return res;
  }



  void
  sendInterest(std::string prefix, Block appParams, int type){

    std::cout << "sending interest with type = " << type << std::endl;
    Name interestName(prefix);
    interestName.appendVersion();
    Interest interest(interestName);

    if( type == 132 || type==133){
      std::cout << "inside if" << std::endl;
      /*auto a = Buffer(appParams.data(),appParams.size());
      auto m = std::make_shared<Buffer>(a);

      Block id_block((uint32_t)303, m);
      id_block.encode();  
      */
      Block inter((uint32_t)type);
      
      inter.insert(inter.elements_end() , appParams);
      inter.encode();
      std::cout << "before setting app params" << std::endl;

      interest.setApplicationParameters( inter );
      std::cout << "after setting app params" << std::endl;
      interest.setMustBeFresh(true);
      interest.setInterestLifetime(10_s); // The default is 4 seconds

      std::cout << "Sending Interest " << interest << std::endl;
      m_face.expressInterest(interest,
                             std::bind(&Producer::onData, this,  _1, _2, prefix),
                             std::bind(&Producer::onNack, this, _1, _2),
                             std::bind(&Producer::onTimeout, this, _1));

      // processEvents will block until the requested data is received or a timeout occurs
      //m_face.processEvents();
    }

  }

  void
  sendData(const Name& prefix, Block content /*std::string content*/){
    auto data = make_shared<Data>(prefix);
    data->setFreshnessPeriod(10_s);
    data->setContent( content);//make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));

    m_keyChain.sign(*data);
    // m_keyChain.sign(*data, signingByIdentity(<identityName>));
    // m_keyChain.sign(*data, signingByKey(<keyName>));
    // m_keyChain.sign(*data, signingByCertificate(<certName>));
    // m_keyChain.sign(*data, signingWithSha256());

    // Return Data packet to the requester
    std::cout << "<< D: " << content << std::endl;
    m_face.put(*data);
  }

private:
  Face m_face;
  KeyChain m_keyChain;
  ScopedRegisteredPrefixHandle m_certServeHandle;
  std::map<std::string, Block> results;
};

} // namespace examples
} // namespace ndn

int
main(int argc, char** argv)
{
  try {
    ndn::examples::Producer producer;
    producer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
