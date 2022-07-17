
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
	std::vector<float> args;
	do {
		std::cin >> a ;
		if( a == "end"){
			break;
		}
		else{
			args.push_back(std::stof(a));
		}
	}
	while (true);


	/*std::vector< unsigned char> vec;
	vec.reserve(args.size());

	for(auto const& s: args)
    {vec.push_back(( unsigned char) std::stoull(s, NULL, 10));}
	*/



	//std::vector<float> myf;
	//myf.push_back(1.0f);
	//myf.push_back(2.0f);
	//myf.push_back(300.0f);
	int length = args.size();
	//for(auto f:args){ std::cout << "before:"<< f << std::endl; }

	const char* bytes = reinterpret_cast<const char*>(&args[0]);

	/*std::vector<unsigned char> byteVec(bytes, bytes + sizeof(float) * size);

	unsigned char* bytes2 = &(byteVec[0]);    // point to beginning of memory
	float* floatArray = reinterpret_cast<float*>(bytes2);

	for (int i = 0; i < 3; i++)
	    std::cout << "after:"<< floatArray[i] << std::endl;  // error here
	*/


	ndn::examples::Consumer consumer; //();
	std::string id = consumer.functionPrefix("/example/test/function");
	std::cout << "consumer id: " << id << std::endl;
	consumer.setArguments(id, bytes, length);

	consumer.execute(id);
	std::cout << "AFTER EXECUTE" << id << std::endl;
	while (consumer.getResponse(id) == "" ) {
		std::cout << "waiting..." << std::endl;
		sleep(100);
	}
	std::string result = consumer.getResponse(id);

	std::cout << "\n Result = " << result << std::endl;

}