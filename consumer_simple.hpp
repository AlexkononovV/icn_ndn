#include <ndn-cxx/face.hpp>
#include <ndn-cxx/security/validator-config.hpp>
#include "ndn-cxx/encoding/tlv.hpp"
#include "ndn-cxx/encoding/block.hpp"
#include <iostream>

#include <cstddef>
#include <bitset>
#include <ndn-cxx/encoding/buffer.hpp>

#include <boost/uuid/uuid.hpp>            // uuid class
#include <boost/uuid/uuid_generators.hpp> // generators
#include <boost/uuid/uuid_io.hpp>         // streaming operators etc.
#include "boost/lexical_cast.hpp"

#include <map>

#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Enclosing code in ndn simplifies coding (can also use `using namespace ndn`)
namespace ndn {
// Additional nested namespaces should be used to prevent/limit name conflicts
namespace examples {

class Consumer
{
public:
	Consumer();

	std::string functionPrefix(std::string pref);
	void explicitParameters(bool value);
	void setArguments(std::string id, const char* arg, int length);//std::vector< unsigned char> arguments); 
  std::string getResponse(std::string id);
	void execute(std::string id);

private:
  void run();
  void onPrefixRegistered(const Name& prefix);
  void onRegisterFailed(const Name& prefix, const std::string& reason);
  void onInterest(const InterestFilter& filter, const Interest& i2);
  void fetchResult(std::string id);


  void onData(const Interest&, const Data& data, std::string id);

  void
  onNack(const Interest&, const lp::Nack& nack) const;

  void
  onTimeout(const Interest& interest) const;

  Face m_face;
  ValidatorConfig m_validator{m_face};
  //std::string prefix="";
  //bool explicit_input = true;
  //std::vector<std::string> params;
  //std::string params;
  RegisteredPrefixHandle m_prefixId;
  KeyChain m_keyChain;
  //std::string *parameters = NULL;
  std::map<std::string, std::string>requests;
  std::map<std::string, std::string>prefixes;
  std::map<std::string, std::string> args;
  std::map<std::string, const char*> data_vec; //std::vector< unsigned char>> data_vec;
  std::map<std::string, int> data_length;
  std::map<std::string, bool> type_input;
  //std::map<std::string, std::string> mem;
  json mem;
};
}
}