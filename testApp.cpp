
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
	int b,  a;
	std::cout << " 1st value: ";
	std::cin >> a ;
	std::cout << " 2nd value: ";
	std::cin >> b;

	std::vector<std::string> args;

	args.push_back(std::to_string(a));
	args.push_back(std::to_string(b)) ;

	//std::cout << sizeof(args[1])*args.size() << std::endl;

	ndn::examples::Consumer consumer; //();
	consumer.functionPrefix("/example/test/function");
	consumer.setArguments(args);
	std::string result = consumer.execute();

}