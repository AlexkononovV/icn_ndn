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

namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {


class ExecInstance {
private:
  std::string id;
  Face m_face; 
  std::string input;
  std::string result;
  KeyChain m_keyChain;

  void
  onData(const Interest&, const Data& data);

  void execute(std::string in);

  void
  onInterestId(const InterestFilter&, const Interest& i);
  void
  onPrefixRegistered(const Name& prefix, std::string ConsumerPrefix);
  void
  onRegisterFailed(const Name& prefix, const std::string& reason);
  void 
  onNack(const Interest& interest, const lp::Nack& nack);
  void
  onTimeout(const Interest& interest);

public:
  bool status;

  ExecInstance(std::string id);

  void
  run(std::string ConsumerPrefix, std::string id);

};

}
}