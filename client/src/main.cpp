#include "http_socket.h"
#include <vector>
#include <cstdlib>

using std::vector;

int main(int argc, char* argv[])
{
	/* default */
	unsigned int worker = 5, loop = 1000;
	unsigned short port = 80;
	stringstream s;
	const string uuid_prefix = "c20aff8a-c457-42b1-a096-";
	string uuid, server, h = "-h", help = "--help";
	CHttpSocket* test = NULL;
	vector<CHttpSocket*> test_array;
	
	if (argc == 2 && (h == argv[1] || help == argv[1])) {
		cout << "Usage: " << argv[0] << " [server] [#port] [#worker] [#loop]" << endl;
		cout << "Default: " << argv[0] << " localhost 80 5 1000" << endl;
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
		s >> worker;
	} else {
		server = argv[1];

		s << argv[2];
		s >> port;
		s.clear();

		s << argv[3];
		s >> worker;
		s.clear();

		s << argv[4];
		s >> loop;
		s.clear();
	}

	if (worker <= 0 || worker > 500) {
		cout << "Limit worker to 500" << endl; 
		worker = 500;
	}

	test_array.reserve(worker);

	for (unsigned int i = 0; i < worker; ++i) {
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
		test = new CHttpSocket(uuid, server, port, "/log_collection", loop);

		if (test) {
			test_array.push_back(test);
			test_array[i]->StartWork();
		}
	}

	for (unsigned int i = 0; i < test_array.size(); ++i) {
		delete test_array[i];
	}

	return 0;
}

