
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


// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

struct ACK {
  std::string code;
  int time;
  std::string id;
};


class Producer
{
public:
  Producer()
  {
    m_validator.load("trust-schema.conf");
  }
  void
  run()
  {
    m_currentSeqNo = 0;
    m_face.setInterestFilter("/testFunction/sum",
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
  onNack(const Interest& interest, const lp::Nack& nack)
  {
    std::cout << "received Nack with reason " << nack.getReason()
              << " for interest I2: " << interest << std::endl;
  }

  void
  onTimeout(const Interest& interest)
  {
    std::cout << "Timeout I2: " << interest << std::endl;
  }
  

  int
  estimate_exec_time()
  {
    std::cout << "\nCalculating execution time ..." << std::endl;
    return 10;
  }

  std::string
  generate_exec_id()
  {
    std::cout << "\nAssigning id to the execution instance ..." << std::endl;

    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    std::string id = boost::lexical_cast<std::string>(uuid);

    return id;
  }
//////////////////////////////////////////////////////////////
  void
  onInterest(const InterestFilter&, const Interest& interest2)
  {
    /*
    if(interest2.getName().getSubName(-3, 1).isPrefixOf(Name("123"))){
        std::cout << ">> I2: " << interest2 << std::endl;

        static std::string content("Result: 5");

        auto data = make_shared<Data>(interest2.getName());
        data->setFreshnessPeriod(10_s);
        data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));

        m_keyChain.sign(*data);

        std::cout << "<< D final sent: \n" << std::endl;
        m_face.put(*data);
     }

     else {*/

        std::cout << ">> I initial: " << interest2 << std::endl;

        ACK *ptr, ack;
        ptr = &ack; 
        (*ptr).code = "OK";
        (*ptr).time = estimate_exec_time();
        (*ptr).id ="123"; //generate_exec_id();
        
        //std::cout << (*ptr).code +":"+boost::lexical_cast<std::string>((*ptr).time)+":"+(*ptr).id << std::endl;

        

        static std::string content((*ptr).code +":"+boost::lexical_cast<std::string>((*ptr).time)+":"+(*ptr).id);

        //static ndn::Block content = ptr;
        auto data = make_shared<Data>(interest2.getName());
        data->setFreshnessPeriod(10_s);
        data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));
        //data->setContent( make_span( ptr, sizeof(struct ACK) ) )

        m_keyChain.sign(*data);

        std::cout << "<< D1 sent. \n" << std::endl;
        m_face.put(*data);


        ExecInstance *execution = new ExecInstance((*ptr).id);
        //execution((*ptr).id);
        execution->run("/consumer/id");

        //register execution instnace 
        //register_exec_id((*ptr).id);
          
          //_________________sending interest to fetch input_____
        /*
          Name interestName("/consumer/id");
           interestName.appendVersion();
           interestName.appendSequenceNumber(m_currentSeqNo);
          Interest interest(interestName);
           interest.setCanBePrefix(false);
           interest.setMustBeFresh(true);
           interest.setInterestLifetime(6_s); // The default is 4 seconds

          m_face.expressInterest(interest,
                                 bind(&Producer::onData, this,  _1, _2, (*ptr).id),
                                 bind(&Producer::onNack, this, _1, _2),
                                 bind(&Producer::onTimeout, this, _1));

          std::cout << ">> sending I1 : " << interest << std::endl;
      */
      //}

  }

/*
  void
  register_exec_id(const std::string id)
  {
    m_face.setInterestFilter("/testFunction/"+id ,
                             std::bind(&Producer::onInterestId, this, _1, _2, id),
                             nullptr, // RegisterPrefixSuccessCallback is optional
                             std::bind(&Producer::onRegisterFailed, this, _1, _2));
  
  }
*/

/*
  void
  onData(const Interest&, const Data& data, const std::string id)
  {
    std::cout << "\nD: " << std::endl;
 
     m_validator.validate(data,
                          [] (const Data&) {
                            std::cout << "Data conforms to trust schema" << std::endl;
                          },
                          [] (const Data&, const security::ValidationError& error) {
                            std::cout << "Error authenticating data: " << error << std::endl;
                          });
    
    std::cerr << "<< input: "
              << std::string(reinterpret_cast<const char*>(data.getContent().value()),
                                                           data.getContent().value_size())
              << std::endl;
   }
*/
  void
  onRegisterFailed(const Name& prefix, const std::string& reason)
  {
    std::cerr << "ERROR: Failed to register prefix '" << prefix
              << "' with the local forwarder (" << reason << ")" << std::endl;
    m_face.shutdown();
  }

  //Face 
  //getFace() { return m_face; }  

private:
  Face m_face;
  KeyChain m_keyChain;
  ScopedRegisteredPrefixHandle m_certServeHandle;
  uint64_t m_currentSeqNo;
  ValidatorConfig m_validator{m_face};

public:

  
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


