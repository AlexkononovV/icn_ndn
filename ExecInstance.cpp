#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>

#include <iostream>

 #include <ndn-cxx/security/validator-config.hpp>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.

#include "boost/lexical_cast.hpp"
#include <boost/algorithm/string.hpp>

#include <vector>
#include <cstdio>

#include "ExecInstance.hpp"

namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {


//class ExecInstance {
/*private:
  std::string id;
  Face m_face; 
  std::string input;
  std::string result;
  KeyChain m_keyChain;
public:
  bool status;
*/
//public:
  ExecInstance::ExecInstance(std::string id)
  {
    id = id;
    //m_face = &Producer.getFace();
    status = false;
    result = "";
  }

  bool
  ExecInstance::run(std::string ConsumerPrefix)
  {
    m_face.setInterestFilter("/testFunction/"+id ,
                             std::bind(&ExecInstance::onInterestId, this, _1, _2),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&ExecInstance::onRegisterFailed, this, _1, _2));
    //m_face.processEvents();
    Name interestName(ConsumerPrefix);
           interestName.appendVersion();
           //interestName.appendSequenceNumber(m_currentSeqNo);
          Interest interest(interestName);
           interest.setCanBePrefix(false);
           interest.setMustBeFresh(true);
           interest.setInterestLifetime(6_s); // The default is 4 seconds

          m_face.expressInterest(interest,
                                 bind(&ExecInstance::onData, this,  _1, _2),
                                 bind(&ExecInstance::onNack, this, _1, _2),
                                 bind(&ExecInstance::onTimeout, this, _1));

          std::cout << ">> sending I1 : " << interest << std::endl;
    m_face.processEvents();
  }

//private:


  void
  ExecInstance::onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest I2: " << interest << std::endl;
  }

  void
  ExecInstance::onTimeout(const Interest& interest)
  {
    std::cout << "Timeout I2: " << interest << std::endl;
  }


  void
  ExecInstance::onData(const Interest&, const Data& data)
  {

    std::string in = std::string(reinterpret_cast<const char*>(data.getContent().value()),
                                                           data.getContent().value_size());
    std::cerr << "<< input: "
              << in
              << std::endl;
    execute(in);
  }

  void ExecInstance::execute(std::string in)
  {
    std::string my_input(in);
    std::vector<std::string> results;

    boost::algorithm::split(results, my_input, boost::is_any_of(","));

    int sum = 0;
    for (std::vector<std::string>::iterator t=results.begin(); t!=results.end(); ++t) 
    { 
        sum += std::stoi(*t); 
    } 
    //sum = 5;
     
    result = std::to_string(sum); 
    status = true;

    std::cout << "\n<< RESULT :" << result << std::endl;
  }

  void
  ExecInstance::onInterestId(const InterestFilter&, const Interest& i)
  { static std::string content;
    if(status) {
      content=result;
    }else {
      content="NACK:10ms";
    }
      

        //static ndn::Block content = ptr;
        auto data = make_shared<Data>(i.getName());
        data->setFreshnessPeriod(10_s);
        data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));
        //data->setContent( make_span( ptr, sizeof(struct ACK) ) )

        m_keyChain.sign(*data);

        std::cout << "\n<< RESULT sent \n" << std::endl;
        m_face.put(*data); 

  }

  void
  ExecInstance::onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

//};

}
}