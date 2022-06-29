
#include <iostream>
#include "consumer_simple.hpp"


struct Msg {
	
	std::string function_prefix;
	std::string content;


};


class testApp {
	
	//std::cout << "    ..." << std::endl;
};

int 
main(int argc, char** argv){

	std::cout << "Program to sum two numbers. " << std::endl;
	int a,b;
	std::cout << " 1st value: ";
	std::cin >> a ;
	std::cout << " 2nd value: ";
	std::cin >> b;
	ndn::examples::Consumer consumer; //();
	consumer.setPrefix("/example/test/function");
	consumer.explicitParameters(true);
	std::string params = "{'input': [" + std::to_string(a) + "," + std::to_string(b) + "],}";
	consumer.setParameters(params);
	consumer.execute();

}