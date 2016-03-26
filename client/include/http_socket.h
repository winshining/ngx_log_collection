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

class CHttpSocket
{
public:
	CHttpSocket(const string& uuid, const string& host = "localhost", const unsigned short port = 80,
		const string& uri = "/", const int m_worker = -1, const int loop = -1, const int timeout = 50);
	~CHttpSocket();

	typedef enum {
		RESPONSE_START,
		RESPONSE_HEADER,
		RESPONSE_INVALID,
		RESPONSE_DONE
	} response_state;

	void	StartWork(void);
	const int& GetConnectionFd(void) const;
	const int& GetEpollFd(void) const;
	struct epoll_event& GetWorkEpollEvent(void);
	const string& GetConnectionReqHeader(void) const;
	const int& GetTimeout(void) const;
	const bool& GetRunState(void) const;
	bool IsLoopDone(void);
	void DecreaseLoop(void);
	void MutexLock(void);
	void MutexUnlock(void);

protected:
	size_t	FormatRequestHeader(void);
	void	Initialize(const string& host, const unsigned short port, const string& uri,
					const int worker, const int loop, const int timeout);
	void	ReInitialize(void);
	void	Finalize(void);

private:
	bool	ResolveServer(struct sockaddr *serv, size_t *servlen);
	void	NonBlockConnect(void);
	response_state	CheckResponse(const string& buffer);
	static	void* DoWork(void *arg);

	struct epoll_event m_connev;
	struct epoll_event m_workev;
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

	pthread_t	*m_tid;
	bool	m_run;
	bool	m_start;

	bool	m_inited;
	static	pthread_mutex_t s_mutex;
	static	const int s_bufsize;
	size_t	m_hdrend;
};

