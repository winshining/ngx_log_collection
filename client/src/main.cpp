#include "http_socket.h"
#include <vector>
#include <cstdlib>

using std::vector;

int main(int argc, char* argv[])
{
	/* default */
	unsigned int sum = 5, worker = 5, loop = 1000;
	unsigned short port = 80;
	stringstream s;
	const string uuid_prefix = "c20aff8a-c457-42b1-a096-";
	string uuid, server, h = "-h", help = "--help";
	CHttpSocket* test = NULL;
	vector<CHttpSocket*> test_array;
	
	if (argc == 2 && (h == argv[1] || help == argv[1])) {
		cout << "Usage: " << argv[0] << " [server] [#port] [#sum] [#worker] [#loop]" << endl;
		cout << "Default: " << argv[0] << " localhost 80 5 5 1000" << endl;
		exit(-1);
	} else if (argc == 1) {
		server = "localhost";
	} else if (argc == 2) {
		server = argv[1];
	} else if (argc == 3) {
		server = argv[1];

		s << argv[2];
		s >> port;
	} else if (argc == 4) {
		server = argv[1];

		s << argv[2];
		s >> port;
		s.clear();

		s << argv[3];
		s >> sum;
	} else if (argc == 5) {
		server = argv[1];

		s << argv[2];
		s >> port;
		s.clear();

		s << argv[3];
		s >> sum;
		s.clear();

		s << argv[4];
		s >> worker;
	} else {
		server = argv[1];

		s << argv[2];
		s >> port;
		s.clear();

		s << argv[3];
		s >> sum;
		s.clear();

		s << argv[4];
		s >> worker;
		s.clear();

		s << argv[5];
		s >> loop;
		s.clear();
	}

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
		test = new CHttpSocket(uuid, argv[1], port, "/log_collection", 5, 1000);

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

