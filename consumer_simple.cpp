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
    m_prefixId = m_face.setInterestFilter("/consumer/id",
                             std::bind(&Consumer::onInterest, this, _1, _2),
                             //RegisterPrefixSuccessCallback(),
                             std::bind(&Consumer::onPrefixRegistered, this, _1),
                             std::bind(&Consumer::onRegisterFailed, this, _1, _2));

    m_face.processEvents();

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
  Consumer::onInterest(const InterestFilter& filter, const Interest& i2){

    std::cout << "\n << I for input \n"  << std::endl;

    
    Name dataName(i2.getName());

    std::string in;
    std::cout << "input: ";
    getline (std::cin, in);
    static const std::string content = in;

    shared_ptr<Data> data = make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); 
    data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));

    // Sign Data packet with default identity
    m_keyChain.sign(*data);

    m_face.put(*data);

    std::cout << ">> sent D with input "  << std::endl;

    //m_face.unsetInterestFilter(m_prefixId);
    //error: ‘class ndn::Face’ has no member named ‘unsetInterestFilter’
  }

  void Consumer::functionPrefix(std::string pref)
  {
    prefix = pref;
  }

  void Consumer::setArguments(std::vector<std::string> args){

    size_t size = sizeof(args[0])*args.size();
    if(size < 1100){
      explicit_input=true; 
      params= "{ 'input':'explicit', 'data': [";
      for( auto s : args ){
        params += (std::string) s + ",";
      }
      params += "]}";
    }
    else{
      explicit_input=false;
      params = "{'input':'implicit', 'prefix': '";
      params +="/consumer/id";
      params += "'}";
    }
      
  }

  std::string Consumer::execute(){

    /*if(prefix.empty())
    {
      std::cout << "ERROR: no function prefix given" << std::endl;
      return 0;
    }*/

    Name interestName(prefix);
    interestName.appendVersion();
    Interest interest(interestName);
    
    //std::string name("testing9");
    if (explicit_input){
      auto a = Buffer(params.data(),params.size());
      auto m = std::make_shared<Buffer>(a);

      Block b((uint32_t)130, m);
      b.encode();      
      interest.setApplicationParameters( b);
    }
    else{
      run();
      std::string msg = "/consumer/id";
      auto a = Buffer(msg.data(),msg.size());
      auto m = std::make_shared<Buffer>(a);

      Block b((uint32_t)131, m);
    }

    interest.setMustBeFresh(true);
    interest.setInterestLifetime(6_s); // The default is 4 seconds

    std::cout << "Sending Interest " << interest << std::endl;
    m_face.expressInterest(interest,
                           std::bind(&Consumer::onData, this,  _1, _2),
                           std::bind(&Consumer::onNack, this, _1, _2),
                           std::bind(&Consumer::onTimeout, this, _1));

    // processEvents will block until the requested data is received or a timeout occurs
    m_face.processEvents();
  }

//private:
  void
  Consumer::onData(const Interest&, const Data& data)
  {
    std::cout << "Received Data " << data << std::endl;
    /*
    m_validator.validate(data,
                         [] (const Data&) {
                           std::cout << "Data conforms to trust schema" << std::endl;
                         },
                         [] (const Data&, const security::ValidationError& error) {
                           std::cout << "Error authenticating data: " << error << std::endl;
                         });
    */
    std::cerr << "\n<< final D:  "
              << std::string(reinterpret_cast<const char*>(data.getContent().value()),
                                                           data.getContent().value_size())
              << std::endl;
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