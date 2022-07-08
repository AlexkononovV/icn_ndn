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
      std::cout << " \n app params: " << std::endl;

      Block b = interest.getApplicationParameters();
      b.parse();
      auto c = b.get(b.elements()[0].type());
      std::string s =std::string(reinterpret_cast<const char*>(c.value()), c.value_size());
      std::cout << s << std::endl;

      int type = b.elements()[0].type();
      
      std::string content;
      json resp;
      json params;
      params = json::parse(s);

      switch(type){
        case 130:{
          std::cout << "interest type 130 " << std::endl;
          //std::string input = parseAppParams();
          if (params["input"]=="explicit"){
            resp["response"]=Sum(s);
            content=resp.dump();

            sendData(interest.getName(),content);

            break;
          }
          
        }
        case 131: {
          if (params["input"]=="implicit"){
            std::cout << "interest type 131 " << std::endl;
            std::string prefix = params["prefix"];
            resp["ACK"]="ACK";
            resp["id"]=params["data"];
            content = resp.dump();

            sendData(interest.getName(),content);

            fetchInput(prefix,resp["id"]);

            std::cout << "after fecth input" << std::endl;
            break;
          }
        }
        case 132: {
          std::cout << "interest type 132 " << std::endl;
          std::string id = params["id"];
          std::string res = results[id];
          resp["response"]=res;
          resp["id"]=id;
          content = resp.dump();

          sendData(interest.getName(),content);
          break;
        }
        default:
         json resp;
         resp["error"]="unknown TLV type";
         content=resp.dump();
         break;
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
    
  }

  std::string
  fetchInput(std::string prefix, std::string id){

    json data;
    data["id"] = id;
    data["response"] = "GET";
    std::string s = data.dump();

    sendInterest(prefix, s, 140);

}

  void
  onData(const Interest&, const Data& data, std::string prefix)
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
    std::string resp = std::string(reinterpret_cast<const char*>(data.getContent().value()),data.getContent().value_size());

    std::cerr << "\n>>D:  "
              << resp
              << std::endl;

    json response;
    response = json::parse(resp);
    //std::string input;

    auto error = response.find("error");
    if( error != response.end() ) {
      std::cout << "ERROR: " << response["error"] << std::endl;
      return;
    }
    auto result = response.find("data");
    if( result != response.end() ) {
      std::cout << "\n recevied data with input" << std::endl;
      std::string input = response["data"].dump();
      std::string result = Sum(resp);
      results[response["id"]] = result;
      json content;
      content["id"] = response["id"];
      content["response"] = "READY";
      std::string s = content.dump();
      //guardar result e madnar um ready
      sendInterest(prefix, s, 141);
      return;
    }
    auto res = response.find("response");
    if( res != response.end() ){
      std::string ack = response["response"].dump();
      std::cout << "A: " << ack << std::endl;
      return;
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

  std::string
  Sum(std::string args){
    json params;
    params = json::parse(args);
    auto values = params["data"];
    std::cout << values << std::endl;
    int sum=0;
    for(std::string i : values){
      std::cout << i << std::endl;
      std::stringstream ss(i);
      int num;
      ss >> num;
      sum += num;
      /*
      std::stringstream strValue;
      strValue << i;
      int intValue;
      strValue >> intValue;
      sum+= intValue;
    */
    }
    return std::to_string(sum);
  }



  void
  sendInterest(std::string prefix, std::string appParams, int type){
    std::cout << "sending interest with type = " << type << std::endl;
    Name interestName(prefix);
    interestName.appendVersion();
    Interest interest(interestName);

    auto a = Buffer(appParams.data(),appParams.size());
    auto m = std::make_shared<Buffer>(a);

    Block b((uint32_t)type, m);
    b.encode();      
    interest.setApplicationParameters( b);

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

  void
  sendData(const Name& prefix, std::string content){
    auto data = make_shared<Data>(prefix);
    data->setFreshnessPeriod(10_s);
    data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));

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
  std::map<std::string, std::string> results;
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
