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


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer
{
public:

  Consumer()
  {
    m_validator.load("trust-schema_default.conf");
  }

  void
  run()
  {
    Name interestName("/example/test/function");
    interestName.appendVersion();

    Interest interest(interestName);
    



    //auto p = "0x240874657374696E6720737472696E6720746C76" ;
    
    const uint8_t text[] = { 0x74, 0x65,0x73,0x74,0x69,0x6E,0x67,0x20,0x73,0x74,0x72,0x69,0x6E,0x67,0x20,0x74,0x6C,0x76 };
    std::cout << sizeof(text) << std::endl;

    const uint8_t data[] = {  
      0x24, //type
      0x13, //size 
      0x74, 0x65,0x73,0x74,0x69,0x6E,0x67,0x20,0x73,0x74,0x72,0x69,0x6E,0x67,0x20,0x74,0x6C,0x76 //value
    };
    /*
    span<const uint8_t> buffer = make_span(reinterpret_cast<const uint8_t*>(p.data()), p.size())  ;
    
    auto pos = buffer.begin();
    const auto end = buffer.end();

    uint32_t m_type = tlv::Invalid;

    m_type = tlv::readType(pos, end);
    uint64_t length = tlv::readVarNumber(pos, end);
    // pos now points to TLV-VALUE

    BOOST_ASSERT(pos <= end);
    std::cout << pos << std::endl;
    std::cout << end << std::endl;
    std::cout << m_type << std::endl;
    std::cout << length << std::endl;
    std::cout << static_cast<uint64_t>(std::distance(pos, end)) << std::endl;

    if (length > static_cast<uint64_t>(std::distance(pos, end))) {
      //NDN_THROW(Error("Not enough bytes in the buffer to fully parse TLV"));
      std::cout << "error" << std::endl;
    }
    */
    

    //std::string p = "DF 82 0A 03 30 31 32";
    //Block b( make_span(reinterpret_cast<const uint8_t*>(p.data), p.size())  ) ;
    //Block b( make_span(reinterpret_cast<const uint8_t*>(p), strlen(p) )  ) ;
    //make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size())
    
    std::string name("testing");

    auto a = Buffer(name.data(),name.size());
    auto m = std::make_shared<Buffer>(a);

    Block b((uint32_t)129, m);
    b.encode();
    //Block* v = &b;
    //std::cout << "\n"<< *v << std::endl;


    //interest.setApplicationParameters( make_span(reinterpret_cast<const uint8_t*>(p.data()), p.size()));
    interest.setApplicationParameters( b);
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

private:
  void
  onData(const Interest&, const Data& data)
  {
    std::cout << "Received Data " << data << std::endl;

    m_validator.validate(data,
                         [] (const Data&) {
                           std::cout << "Data conforms to trust schema" << std::endl;
                         },
                         [] (const Data&, const security::ValidationError& error) {
                           std::cout << "Error authenticating data: " << error << std::endl;
                         });
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

private:
  Face m_face;
  ValidatorConfig m_validator{m_face};
};

} // namespace examples
} // namespace ndn

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
