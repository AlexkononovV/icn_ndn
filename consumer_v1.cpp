
 
#include <ndn-cxx/face.hpp>
 #include <ndn-cxx/security/validator-config.hpp>
 #include <ndn-cxx/security/key-chain.hpp>

 #include <iostream>
 
 // Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
 namespace ndn {
 // Additional nested namespaces should be used to prevent/limit name conflicts
 namespace examples {
 
 class Consumer
 {
 public:
   Consumer()
   {
     m_validator.load("trust-schema.conf");

   }
 
   void
   run()
   {
    m_currentSeqNo=0;
    m_prefixId = m_face.setInterestFilter("/consumer/id",
                             std::bind(&Consumer::onInterest, this, _1, _2),
                             //RegisterPrefixSuccessCallback(),
                             std::bind(&Consumer::onPrefixRegistered, this, _1),
                             std::bind(&Consumer::onRegisterFailed, this, _1, _2));



    Name interestName("/testFunction/sum");
       interestName.appendVersion();
       interestName.appendSequenceNumber(m_currentSeqNo);
      Interest interest(interestName);
       interest.setCanBePrefix(false);
       interest.setMustBeFresh(true);
       interest.setInterestLifetime(6_s); // The default is 4 seconds

      m_face.expressInterest(interest,
                             bind(&Consumer::onData1, this,  _1, _2),
                             bind(&Consumer::onNack, this, _1, _2),
                             bind(&Consumer::onTimeout, this, _1));

      std::cout << "\n >>  I1 : " << interest << std::endl;


    m_face.processEvents();

   }

 
 private:
  
  void onPrefixRegistered(const Name& prefix) {

    std::cout << "\nPrefix " << prefix << " registered." << std::endl;

  }

  void
  onInterest(const InterestFilter& filter, const Interest& i2){

    std::cout << "\n << I for input \n"  << std::endl;

    Name dataName(i2.getName());

    static const std::string content = "10,3";

    shared_ptr<Data> data = make_shared<Data>();
    data->setName(dataName);
    data->setFreshnessPeriod(10_s); 
    data->setContent(make_span(reinterpret_cast<const uint8_t*>(content.data()), content.size()));

    // Sign Data packet with default identity
    m_keyChain.sign(*data);

    m_face.put(*data);

    std::cout << ">> sent D2 with input "  << std::endl;

    //m_face.unsetInterestFilter(m_prefixId);
    //error: ‘class ndn::Face’ has no member named ‘unsetInterestFilter’

    fetchData();
  }


  void
  fetchData() {
    Name interestName("/testFunction/123");
       interestName.appendVersion();
       interestName.appendSequenceNumber(m_currentSeqNo);
      Interest interest(interestName);
       interest.setCanBePrefix(true);
       interest.setMustBeFresh(true);
       interest.setInterestLifetime(6_s); // The default is 4 seconds

      m_face.expressInterest(interest,
                             bind(&Consumer::onData2, this,  _1, _2),
                             bind(&Consumer::onNack, this, _1, _2),
                             bind(&Consumer::onTimeout, this, _1));

      std::cout << "\n >> sending I to get results : " << interest << std::endl;


    }


  void
   onData1(const Interest&, const Data& data)
   {
     std::cout << "\n D received :"  << data << std::endl;
     /*
     m_validator.validate(data,
                          [] (const Data&) {
                            std::cout << "Data conforms to trust schema" << std::endl;
                          },
                          [] (const Data&, const security::ValidationError& error) {
                            std::cout << "Error authenticating data: " << error << std::endl;
                          });
      */
    std::cerr << " <<  "
              << std::string(reinterpret_cast<const char*>(data.getContent().value()),
                                                           data.getContent().value_size())
              << std::endl;

  
   }


  void
   onData2(const Interest&, const Data& data)
   {
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

   std::cout << "\nfinish "<< std::endl;
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
 
 private:
   Face m_face;
   ValidatorConfig m_validator{m_face};
   uint64_t m_currentSeqNo;

   RegisteredPrefixHandle m_prefixId;
   KeyChain m_keyChain;
 };
 
 } // namespace examples
 } // namespace ndn
 
 int
 main(int argc, char** argv)
 {
   try {
    ndn::examples::Consumer consumer;
    std::cerr << "Running client: " << std::endl;
    consumer.run();
    return 0;
  }
  catch (const std::exception& e) {
    std::cerr << "ERROR: " << e.what() << std::endl;
    return 1;
  }
}