#include <windows.h>
#include <string>
#include <iostream>


class Simple {
private:
	int Points;
	std::string Name;
	std::string SerName;
public:
	Simple(std::string _Name, std::string _SerName, int _Points = 0) :
		Name(_Name) , SerName(_SerName) , Points(_Points)
	{

	}

	//will hook this function
	void __thiscall PrintInfo() {
		std::cout << "Name : " << Name << "\tSername : " << SerName <<
			"\tPoints : " << std::hex << Points << std::endl;
	}
};

int main() {
	getchar(); //for inject dll
	Simple ob("Name1", "SerName1" , 0xdeadbeef);;
	ob.PrintInfo();

	Sleep(100000);
	return 0;
}