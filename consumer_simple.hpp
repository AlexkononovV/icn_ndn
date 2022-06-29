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
	Consumer();

	void setPrefix(std::string pref);
	void explicitParameters(bool value);
	void setParameters(std::string params);
	int execute();

private:
  void run();
  void onPrefixRegistered(const Name& prefix);
  void onRegisterFailed(const Name& prefix, const std::string& reason);
  void onInterest(const InterestFilter& filter, const Interest& i2);


  void onData(const Interest&, const Data& data);

  void
  onNack(const Interest&, const lp::Nack& nack) const;

  void
  onTimeout(const Interest& interest) const;

  Face m_face;
  ValidatorConfig m_validator{m_face};
  std::string prefix="";
  bool explicit_input = true;
  std::string params;
  RegisteredPrefixHandle m_prefixId;
  KeyChain m_keyChain;
  //std::string *parameters = NULL;
};
}
}