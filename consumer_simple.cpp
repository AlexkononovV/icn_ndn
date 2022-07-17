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
#include <ndn-cxx/security/validator-config.hpp>
#include "ndn-cxx/encoding/tlv.hpp"
#include "ndn-cxx/encoding/block.hpp"
#include <iostream>

#include <cstddef>
#include <bitset>
#include <ndn-cxx/encoding/buffer.hpp>

#include "consumer_simple.hpp"
#include <boost/regex.hpp>

#include <nlohmann/json.hpp>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include <map>


// for convenience
using json = nlohmann::json;


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

//class Consumer{
//public:

  Consumer::Consumer()
  {
    m_validator.load("trust-schema_default.conf");
    //prefix = f_prefix;
  }

  void
  Consumer::run()
   {
    
    //m_currentSeqNo=0;
    m_prefixId = m_face.setInterestFilter("/consumer/sum/1",
                             std::bind(&Consumer::onInterest, this, _1, _2),
                             //RegisterPrefixSuccessCallback(),
                             std::bind(&Consumer::onPrefixRegistered, this, _1),
                             std::bind(&Consumer::onRegisterFailed, this, _1, _2));

    //m_face.processEvents();

  }

  
  void Consumer::onPrefixRegistered(const Name& prefix) {

    std::cout << "\nPrefix " << prefix << " registered." << std::endl;
  }

  void
  Consumer::onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

  void
  Consumer::onInterest(const InterestFilter& filter, const Interest& interest){
      
    if( interest.hasApplicationParameters() ) {

      //std::cout << ">> I: " << interest << std::endl;
      std::cout << " \n app params: " << std::endl;

      Block inter = interest.getApplicationParameters();
      inter.parse();
      int type = inter.elements()[0].type();
      
      //Block content((uint32_t)520);
      

      switch(type){
        case 132:{
          Block in = inter.get(132);
          in.parse();
          std::cout << "interest type 132 " << std::endl;
          //get id
          Block block_id = in.get(303);
          std::string id =std::string(reinterpret_cast<const char*>(block_id.value()), block_id.value_size());
          
          //get input to put in block
          const char* aux = data_vec[id];
          int size = sizeof aux * data_length[id];
          auto a_buf = Buffer(aux, size);
          auto b_buf = std::make_shared<Buffer>(a_buf);
          Block buffer((uint32_t)300, b_buf);
          buffer.encode();

          int length = data_length[id];
          const char* bytes = reinterpret_cast<const char*>(&length);
          auto a2_buf = Buffer(bytes, 4); 
          auto b2_buf = std::make_shared<Buffer>(a2_buf);
          Block length_block((uint32_t)301, b2_buf);
          length_block.encode();

          Block data_block((uint32_t)200);
          data_block.insert(data_block.elements_end() ,buffer);
          data_block.insert(data_block.elements_end() ,length_block);
          data_block.encode();

          Block content((uint32_t)520);
          content.insert(content.elements_end() ,data_block);
          content.insert(content.elements_end() ,block_id);
          content.encode();

          auto data = make_shared<Data>(interest.getName());
          data->setFreshnessPeriod(10_s);
          data->setContent( content );

          m_keyChain.sign(*data);

          m_face.put(*data);

          std::cout << "<< D: " << *data << std::endl;
          //m_face.processEvents(); ///!!! com isto aqui responde ao interest 140 mas nao ao 141
          break;
        }
        case 133: {
          Block in = inter.get(133);
          in.parse();
          std::cout << "interest type 133 " << std::endl;
          Block block_id = in.get(303);
          std::string id =std::string(reinterpret_cast<const char*>(block_id.value()), block_id.value_size());

          Block content((uint32_t)521);
          content.insert(content.elements_end() ,block_id);
          content.encode();

          auto data = make_shared<Data>(interest.getName());
          data->setFreshnessPeriod(10_s);
          data->setContent(content);

          m_keyChain.sign(*data);

          std::cout << "<< D: " << *data << std::endl;
          m_face.put(*data);
          //m_face.processEvents();
          std::cout << "data response to 133 sent" << std::endl;
          //-----------------------------------------
          fetchResult(id);
          std::cout << "after fetch result 174" << std::endl;
          break;
        }
        default:
         std::cout << "Unknown type" << std::endl;
         break;
      }
    }
  }

  void
  Consumer::fetchResult(std::string id){
    
    auto a2 = Buffer(id.data(),id.size());
    auto m2 = std::make_shared<Buffer>(a2);

    Block id_block((uint32_t)303, m2);
    id_block.encode();  

    Block inter((uint32_t)135);
    inter.insert(inter.elements_end() ,id_block);
    inter.encode();

    Name interestName(prefixes[id]);
    interestName.appendVersion();
    Interest interest(interestName);

    interest.setApplicationParameters( inter );
    interest.setMustBeFresh(true);
    interest.setInterestLifetime(6_s); // The default is 4 seconds

    std::cout << "Sending Interest " << interest << std::endl;
    m_face.expressInterest(interest,
                           std::bind(&Consumer::onData, this,  _1, _2, id),
                           std::bind(&Consumer::onNack, this, _1, _2),
                           std::bind(&Consumer::onTimeout, this, _1));
    // processEvents will block until the requested data is received or a timeout occurs
    //m_face.processEvents();
    std::cout << "result fetched !!! " << std::endl;
  }

  std::string
  Consumer::functionPrefix(std::string pref)
  {
    //prefix = pref;
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    std::string id = boost::lexical_cast<std::string>(uuid);

    requests[id] = ""; //resultado da execução 
    prefixes[id] = pref; //prefixo da função para ser executada
    args[id]="";  // buffer para colocar argumentos de input 
    mem[id] = "";
    consumer_prefix[id]="/consumer/sum/1";
    return id;

  }

  void Consumer::setArguments(std::string id, const char* arguments, int length){ //std::vector<unsigned char> arguments){ 

    //size_t size = sizeof(arguments[0])*arguments.size();
    // ---->size_t size = sizeof(arguments) * length;
    //int size = strlen((const char*)arguments);
    int size = sizeof arguments * length;
    /*for (std::vector<const char*>::const_iterator cit = arguments.begin(); cit != arguments.end(); ++cit) {
        size += sizeof cit;
    }*/
    data_vec[id] = arguments;
    data_length[id]=length;
    std::cout << "size of args : " << size << std::endl;
    if(size < 80){ 
      type_input[id]=1;
    }
    else{
      type_input[id]=0;
  }
}

  std::string
  Consumer::getResponse(std::string id){
    
    return requests[id];
  }


  void
  Consumer::execute(std::string id){

    /*if(prefix.empty())
    {
      std::cout << "ERROR: no function prefix given" << std::endl;
      return 0;
    }*/

    Name interestName(prefixes[id]);
    interestName.appendVersion();
    Interest interest(interestName);
    
    //std::string name("testing9");

    /*json data;
    data = json::parse(args[id]);*/

    if (type_input[id]){
      std::cout << "implicit arguments" << std::endl;
      //std::string s = data.dump();
      //std::vector< unsigned char> aux = data_vec[id]; //data["data"]; //.get<std::vector<const char*>>();
      const char* aux = data_vec[id];
      int size = sizeof aux * data_length[id];
      std::cout << "size of buffer: " << size << std::endl;
      //auto a = Buffer(aux.data(),aux.size());
      auto a_buf = Buffer(aux, size);
      auto b_buf = std::make_shared<Buffer>(a_buf);
      Block buffer((uint32_t)300, b_buf);
      buffer.encode();

      int length = data_length[id];
      /*std::vector<unsigned char> length_arr(4);
      for (int i = 0; i < 4; i++)
      {     length_arr[3 - i] = (length >> (i * 8));
       }*/
      const char* bytes = reinterpret_cast<const char*>(&length);
      auto a2_buf = Buffer(bytes, 4); //length_arr.data(), length_arr.size());
      auto b2_buf = std::make_shared<Buffer>(a2_buf);
      Block length_block((uint32_t)301, b2_buf);
      length_block.encode();

      Block data((uint32_t)200);
      data.insert(data.elements_end() ,buffer);
      data.insert(data.elements_end() ,length_block);
      data.encode();

      int type=130;
      Block appParam((uint32_t)type);
      //b.push_back(tst);  
      //std::cout << "elementa_end = " << b.elements_end() << std::endl;
      //out.insert(b.elements_end() ,tst);
      appParam.insert(appParam.elements_end() ,data);
      appParam.encode();      
      interest.setApplicationParameters( appParam);
    }
    else{
      run();

      std::string prefix = consumer_prefix[id]; //data["prefix"];

      auto a = Buffer(id.data(),id.size());
      auto b = std::make_shared<Buffer>(a);
      Block id_block((uint32_t)303, b);
      id_block.encode();

      auto a2 = Buffer(prefix.data(),prefix.size());
      auto b2 = std::make_shared<Buffer>(a2);
      Block prefix_block((uint32_t)302, b2);
      prefix_block.encode();


      int type=131;
      //if( type == 1){t=131; }
      //else if (type ==2 ){t=151; }

      Block appParam((uint32_t)type);
      
      appParam.insert(appParam.elements_end() ,id_block);
      appParam.insert(appParam.elements_end() ,prefix_block);
      appParam.encode();      
      interest.setApplicationParameters( appParam);
    }

    interest.setMustBeFresh(true);
    interest.setInterestLifetime(6_s); // The default is 4 seconds

    std::cout << "Sending Interest " << interest << std::endl;
    m_face.expressInterest(interest,
                           std::bind(&Consumer::onData, this,  _1, _2, id),
                           std::bind(&Consumer::onNack, this, _1, _2),
                           std::bind(&Consumer::onTimeout, this, _1));

    // processEvents will block until the requested data is received or a timeout occurs
    m_face.processEvents();
    
    //generate id for fetching results
    
  }

//private:
  void
  Consumer::onData(const Interest&, const Data& data, std::string id)
  {
    //std::cout << "Received Data " << data << std::endl;
    /*
    m_validator.validate(data,
                         [] (const Data&) {
                           std::cout << "Data conforms to trust schema" << std::endl;
                         },
                         [] (const Data&, const security::ValidationError& error) {
                           std::cout << "Error authenticating data: " << error << std::endl;
                         });
    */
    /*std::string resp = std::string(reinterpret_cast<const char*>(data.getContent().value()),data.getContent().value_size());

    std::cerr << "\n<<D:  "
              << resp
              << std::endl;
    */
    Block response = data.getContent();
    response.parse();
    int type = response.elements()[0].type();
    std::string id2 ="";
    //json response;
    //response = json::parse(resp);
    /*
    auto error = response.find("error");
    if( error != response.end() ) {
      std::cout << "ERROR: " << response["error"] << std::endl;
      return;
    }
    auto result = response.find("response");
    if( result != response.end() ) {
      requests[id] = response["response"].dump();
      return;
    }
    auto ack = response.find("ACK");
    if( ack != response.end() ) {
      std::cout << "\n waiting for interest to fetch input" << std::endl;
      //m_face.processEvents();
      return;
    }*/
    std::cout << "D received, type: " << type << std::endl;
    switch(type){
        case 500:{
          Block in = response.get(type);
          in.parse();
          for ( auto i2: in.elements() )
            { 
              std::cout << "element inside content block : " << i2 << std::endl;
              if (i2.type() == 501){
                auto c = in.get(501);
                std::string s =std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
                requests[id] = s;
              }
              if (i2.type() == 303){
                std::cout << "ACK, waiting interest" << std::endl;
              }
            }

          break;
        }
        case 510:
        {
          std::cout << "inside case 510" << std::endl;
          Block in = response.get(type);
          in.parse();
          std::string result;
          std::cout << "inside case 510:before for" << std::endl;
          for ( auto i2: in.elements() )
          { 
            if( i2.type() == 303 ){
              auto c = in.get(303);
              id2 =std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
              std::cout << "inside case 510:found 303 : " << id2 << std::endl;

            }
            if( i2.type() == 501){
              auto c = in.get(501);
              result =std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
              std::cout << "inside case 510:found 501 : " << result << std::endl;
            }
          }
          if (id2 != ""){
            requests[id2]=result;
          }

          std::cout << "id: " << id2 << std::endl;
          std::cout << "requests : " << id2 << std::endl;
          m_face.shutdown();
          break;
        }
        default:
         std::cout << "unknown type" << std::endl;
         break;
    }
  }

  void
  Consumer::onNack(const Interest&, const lp::Nack& nack) const
  {
    std::cout << "Received Nack with reason " << nack.getReason() << std::endl;
  }

  void
  Consumer::onTimeout(const Interest& interest) const
  {
    std::cout << "Timeout for " << interest << std::endl;
  }

//private:
//  Face m_face;
//  ValidatorConfig m_validator{m_face};
//};

} // namespace examples
} // namespace ndn

/*
int
main(int argc, char** argv)
{
  try {
    ndn::examples::Consumer consumer;
    consumer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}
*/