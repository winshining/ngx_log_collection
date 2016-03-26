#include "http_socket.h"
#include <vector>
#include <cstdlib>

using std::vector;

int main(int argc, char* argv[])
{
	unsigned int sum;
	stringstream s;
	const string uuid_prefix = "c20aff8a-c457-42b1-a096-";
	string uuid;
	CHttpSocket* test = NULL;
	vector<CHttpSocket*> test_array;
	
	if (argc != 3) {
		cout << "Usage: " << argv[0] << " server #loop" << endl;
		exit(-1);
	}

	s << argv[2];
	s >> sum;

	if (sum <= 0 || sum > 500) {
		sum = 500;
	}

	test_array.reserve(sum);

	for (unsigned int i = 0; i < sum; ++i) {
		s.clear();
		s.str("");
		uuid.clear();

		s << i;
		s >> uuid;

		string::size_type size = uuid.size();
		for (unsigned int j = 0; j < 12 - size; ++j) {
			uuid = "0" + uuid;
		}

		uuid = uuid_prefix + uuid;
		test = new CHttpSocket(uuid, argv[1], 80, "/log_collection", 5, 1000);

		if (test) {
			test_array.push_back(test);
		}
	}

	for (unsigned int i = 0; i < test_array.size(); ++i) {
		test_array[i]->StartWork();
	}

	for (unsigned int i = 0; i < test_array.size(); ++i) {
		delete test_array[i];
	}

	return 0;
}

