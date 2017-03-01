#include <cstdio>
#include <sys/epoll.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

using std::cout;
using std::endl;
using std::string;
using std::stringstream;

typedef enum {
	RESPONSE_START,
	RESPONSE_HEADER,
	RESPONSE_INVALID,
	RESPONSE_DONE
} RespState;

class CHttpSocket
{
public:
	CHttpSocket(const string& uuid, const string& host = "localhost",
		const unsigned short port = 80, const string& uri = "/",
		const int loop = -1, const int timeout = 50);
	~CHttpSocket();

	void	StartWork(void);
	const int& GetConnectFd(void) const;
	const int& GetEpollFd(void) const;
	const string& GetReqHeader(void) const;
	const int& GetTimeout(void) const;
	const int& GetLoop(void) const;
	int		SetNonBlockConnect(void);
	bool	CheckConnectError(void);

protected:
	size_t	FormatRequestHeader(void);
	void	Initialize(const string& host, const unsigned short port,
				const string& uri, const int loop, const int timeout);
	bool	ReInitialize(struct epoll_event& ev);
	void	Finalize(void);

private:
	bool	ResolveServer(struct sockaddr *serv, size_t *servlen);
	RespState	CheckResponse(const string& buffer);
	static	void* DoWork(void *arg);

	string	m_req;

	string	m_host;
	string	m_port;
	string	m_uri;
	string	m_uuid;

	int		m_timeout;

	int		m_epollfd;
	int		m_connfd;
	int		m_worker;
	int		m_loop;
	int		m_pipeline;
	int		m_hdrend;

	pthread_t	m_tid;

	bool	m_inited;
	static	const int s_bufsize;
};

