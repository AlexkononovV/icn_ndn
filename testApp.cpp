
#include <iostream>
#include "consumer_simple.hpp"
#include <stdlib.h> 

struct Msg {
	
	std::string function_prefix;
	std::string content;


};


class testApp {
	
	//std::cout << "    ..." << std::endl;
};

int 
main(int argc, char** argv){

	std::cout << "Program to numbers. " << std::endl;
	std::string a;
	std::vector<std::string> args;
	do {
		std::cin >> a ;
		if( a == "end"){
			break;
		}
		else{
			args.push_back(a);
		}
	}
	while (true);
	
	/*nt b,  a;
	std::cout << " 1st value: ";
	std::cin >> a ;
	std::cout << " 2nd value: ";
	std::cin >> b;

	std::vector<std::string> args;

	args.push_back(std::to_string(a));
	args.push_back(std::to_string(b)) ;
*/
	//std::cout << sizeof(args[1])*args.size() << std::endl;

	ndn::examples::Consumer consumer; //();
	std::string id = consumer.functionPrefix("/example/test/function");


	std::vector<const char*> buff(args.size(),nullptr);
	
	for (int i=0; i<args.size();i++) {
	    buff[i]= args[i].c_str();
	}
	//std::cout << charVec << std::endl;

	consumer.setArguments(id, buff);
	consumer.execute(id);
	while (consumer.getResponse(id) == "" ) {
		std::cout << "waiting..." << std::endl;
		sleep(100);
	}
	std::string result = consumer.getResponse(id);

	std::cout << "\n Result = " << result << std::endl;

}