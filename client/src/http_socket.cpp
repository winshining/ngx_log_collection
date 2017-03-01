#include "http_socket.h"

const int CHttpSocket::s_bufsize = 2048;

CHttpSocket::CHttpSocket(const string& uuid, const string& host,
		const unsigned short port, const string& uri,
		const int loop, const int timeout)
{
	Initialize(host, port, uri, loop, timeout);

	if (uuid.empty()) {
		Finalize();
		cout << pthread_self() << ": empty uuid in construction" << endl;
	} else {
		m_uuid = uuid;
		m_inited = true;
	}
}

CHttpSocket::~CHttpSocket()
{
	Finalize();
}

size_t CHttpSocket::FormatRequestHeader(void)
{
	m_req.clear();
	m_req += "POST ";
	m_req += m_uri;
	m_req += " HTTP/1.1";
	m_req += "\r\n";

	m_req += "Host: ";
	m_req += m_host;
	m_req += "\r\n";

	if (m_uuid.size() != 0) {
		m_req += "Client-UUID: ";
		m_req += m_uuid;
		m_req += "\r\n";
	}

	m_req += "Accept: */*";
	m_req += "\r\n";

	m_req += "Connection: Keep-Alive";
	m_req += "\r\n";

	m_req += "Content-Type: application/x-www-form-urlencoded";
	m_req += "\r\n";

	m_req += "Content-Length: ";

	return (size_t) m_req.size();
}

void CHttpSocket::StartWork()
{
	int ret;

	if (!m_inited) {
		return;
	}

	FormatRequestHeader();

	ret = pthread_create(&m_tid, NULL, CHttpSocket::DoWork, (void *)this);
	if (ret != 0) {
		cout << pthread_self() << ": create thread failed:" << strerror(errno) << endl;
		return;
	}

	m_hdrend = 0;
	m_pipeline = 0;
	cout << m_tid << " is running" << endl;
}

RespState CHttpSocket::CheckResponse(const string& buffer)
{
	string::size_type pos = 0;
	string size;
	stringstream ss;
	RespState s = RESPONSE_START;

	if (buffer.empty()) {
		return (m_hdrend > 0) ? RESPONSE_START : RESPONSE_HEADER;
	}

	for ( ;; ) {
		if (m_hdrend > 0) {
			for ( ;; ) {
				/* Content-Length */
				pos = buffer.find("Content-Length:", pos);
				if (pos == string::npos) {
					if (m_pipeline == 0) {
						m_hdrend = 0;
						pos = 0;
						break;
					} else {
						return RESPONSE_HEADER; 
					}
				} else {
					m_pipeline++;
					if (m_pipeline > 2) {
						m_hdrend = 0;
						m_pipeline = 0;
						return RESPONSE_DONE;
					}
				}
			} 

			for ( ;; ) {
				/* Transfer-Encoding */
				pos = buffer.find("Transfer-Encoding:", pos);

				if (pos == string::npos) {
					if (m_pipeline == 0) {
						m_hdrend = 0;
						return RESPONSE_INVALID;
					} else {
						return RESPONSE_HEADER;
					}
				} else {
					m_pipeline++;
					if (m_pipeline > 2) {
						m_pipeline = 0;
						m_hdrend = 0;
						return RESPONSE_DONE;
					}
				}
			}
		} else {
			pos = buffer.find("\r\n\r\n", pos);

			if (pos != string::npos) {
				m_hdrend = (size_t) pos;
				s = RESPONSE_HEADER;
			} else {
				break;
			}
		}
	}

	return s;
}

void* CHttpSocket::DoWork(void *arg)
{
	const string str = "content=This+is+a+test+string+in+the+log+collection+client"
		"+programm%2C+first+coded+on+2016.03.08+by+Xingyuan+Wang%2C"
		"+which+is+used+to+test+the+log+collection+server+module+in+"
		"nginx,+versions+1.2.6,+1.8.1+and+1.9.12+were+tested+on+2016"
		"-10-10-15.%0D%0AThe+following+blanks+is+intended+to+tested+"
		"the+urldecode+functionality+of+the+module:           %0D%0A";

	stringstream s;
	string size, req;
	ssize_t all, r = 0, delta_in = 0, delta_out = 0;
	int n, i, j;
	char buffer[s_bufsize];
	struct epoll_event ev, events[10];
	bool connected = false, done;
	pthread_t tid = pthread_self();

	CHttpSocket* obj = (CHttpSocket*) arg;
	const string& reqh = obj->GetReqHeader();

	s << str.size();
	s >> size;
	req = reqh + size + "\r\n\r\n";
	req += str;
	req += reqh + size + "\r\n\r\n";
	req += str;
	req += reqh + size + "\r\n\r\n";
	req += str;
	all = req.size();

	signal(SIGPIPE, SIG_IGN);

	r = obj->SetNonBlockConnect();
	if (r == -1 && errno != EINPROGRESS) {
		cout << "Set nonblock connect failed." << endl;
		return NULL;
	}

	const int& connfd = obj->GetConnectFd();
	const int& epollfd = obj->GetEpollFd();
	const int& timeout = obj->GetTimeout();

	ev.events = EPOLLOUT | EPOLLET;
	ev.data.fd = connfd;
	n = epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev);
	if (n == -1) {
		cout << tid << ": Add the connect socket for write failed: " << strerror(errno) << endl;
		return NULL;
	}

	for (i = 0; i < obj->GetLoop(); i++) {
		done = false;

		for ( ;; ) {
			n = epoll_wait(epollfd, events, 10, timeout);
			if (n == -1) {
				if (errno != EINTR) {
					cout << tid << ": Epoll failed: " << strerror(errno) << endl;
					return NULL;
				}
			} else if (n > 0) {
				for (j = 0; j < n; j++) {
					/* only one fd, so we do not check it */
					if (!connected) {
						if (!obj->CheckConnectError()) {
							cout << tid << ": Connect error happened." << endl;
							return NULL;
						} else {
							ev.events |= EPOLLIN;
							n = epoll_ctl(epollfd, EPOLL_CTL_MOD, connfd, &ev);
							if (n == -1 && errno != EINTR) {
								cout << tid << ": Add the connect socket for read failed: " <<
									strerror(errno) << endl;

								return NULL;
							}

							connected = true;
						}
					} else {
						if (events[j].events & EPOLLOUT) {
							/* send */
							while (delta_out < all) {
								r = send(connfd, req.c_str() + delta_out, req.size() - delta_out, 0);
								if (r == -1) {
									if (errno != EINTR && errno != EAGAIN) {
										cout << tid << ": Send error: " << strerror(errno) << endl;
										return NULL;
									}

									if (errno == EAGAIN) {
										delta_out = 0;
										break;
									}
								} else {
									if (delta_out >= all) {
										delta_out = 0;
										break;
									}

									delta_out += r;
								}
							}
						}

						if (events[j].events & EPOLLIN) {
							/* recv */
							for ( ;; ) {
								r = recv(connfd, buffer + delta_in, s_bufsize - delta_in, 0);
								if (r == -1) {
									if (errno != EINTR && errno != EAGAIN) {
										cout << tid << ": Recv error: " << strerror(errno) << endl;
										return NULL;
									} else {
										break;
									}
								} else if (r == 0) {
									delta_in = 0;
									cout << tid << ": Peer closed the connection." << endl;
									if (!obj->ReInitialize(ev)) {
										return NULL;
									}

									connected = false;
									break;
								} else {
									delta_in += r;

									RespState s = obj->CheckResponse(string(buffer));
									if (s == RESPONSE_DONE) {
										delta_in = 0;
										done = true;
										break;
									}
								}
							}
						}
					}
				}
			} else {
				if (done) {
					if (i == obj->GetLoop() - 1) {
						break;
					}

					delta_out = 0;
					while (delta_out < all) {
						r = send(connfd, req.c_str() + delta_out, req.size() - delta_out, 0);
						if (r == -1) {
							if (errno != EINTR && errno != EAGAIN) {
								cout << tid << ": Send error: " << strerror(errno) << endl;
								return NULL;
							}

							if (errno == EAGAIN) {
								continue;
							}
						} else {
							if (delta_out >= all) {
								delta_out = 0;
								break;
							}

							delta_out += r;
						}
					}

					break;
				}

				cout << tid << ": Epoll timeout." << endl;
			}
		}
	}

	return NULL;
}

void CHttpSocket::Initialize(const string& host, const unsigned short port,
	const string& uri, const int loop, const int timeout)
{
	m_connfd = -1;
	m_inited = false;
	m_tid = 0;

	m_host = host.empty() ? "localhost" : host;
	stringstream s;
	s << port;
	s >> m_port;
	m_uri = uri.empty() ? "/" : uri;
	m_loop = (loop <= 0) ? 50 : loop;
	m_timeout = (timeout <= 0) ? 50 : timeout;

	m_epollfd = epoll_create(10);
	if (m_epollfd == -1) {
		Finalize();
	}
}

bool CHttpSocket::ReInitialize(struct epoll_event& ev)
{
	int r, n;
	pthread_t tid = pthread_self();

	epoll_ctl(m_epollfd, EPOLL_CTL_DEL, m_connfd, NULL);
	close(m_connfd);
	m_connfd = -1;

	r = SetNonBlockConnect();
	if (r == -1 && errno != EINPROGRESS) {
		cout << "Set nonblock connect failed." << endl;
		return false;
	}

	ev.events = EPOLLOUT | EPOLLET;
	ev.data.fd = m_connfd;

	n = epoll_ctl(m_epollfd, EPOLL_CTL_ADD, m_connfd, &ev);
	if (n == -1) {
		cout << tid << ": Add the connect socket for write failed: " << strerror(errno) << endl;
		return false;
	}

	return true;
}

void CHttpSocket::Finalize(void)
{
	if (m_tid > 0) {
		pthread_join(m_tid, NULL);
		cout << m_tid << " joined" << endl;
	}

	if (m_epollfd >= 0) {
		if (m_connfd >= 0) {
			epoll_ctl(m_epollfd, EPOLL_CTL_DEL, m_connfd, NULL);
		}

		close(m_epollfd);
		m_epollfd = -1;
	}

	if (m_connfd >= 0) {
		close(m_connfd);
		m_connfd = -1;
	}

	m_inited = false;
	m_loop = 0;
}

bool CHttpSocket::ResolveServer(struct sockaddr *serv, size_t *servlen)
{
	int r;
	struct addrinfo hints, *res, *ressave;

	bzero(&hints, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;

	r = getaddrinfo(m_host.c_str(), m_port.c_str(), &hints, &res);
	if (r != 0) {
		cout << pthread_self() << ": getaddrinfo error: " << gai_strerror(r) << endl;
		return false;
	}

	ressave = res;

	do {
		m_connfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (m_connfd > 0) {
			*servlen = res->ai_addrlen;
			bcopy(res->ai_addr, serv, *servlen);
			break;
		}
	} while((res = res->ai_next) != NULL);

	freeaddrinfo(ressave);

	if (res == NULL) {
		/* found nothing */
		cout << pthread_self() << ": " << m_host << " " << m_port << " not found" << endl;
		return false;
	}

	return true;
}

int CHttpSocket::SetNonBlockConnect(void)
{
	struct sockaddr srv;
	size_t addrlen;
	int	r = -1;

	if (ResolveServer(&srv, &addrlen)) {
		int val = fcntl(m_connfd, F_GETFL, 0);
		if (fcntl(m_connfd, F_SETFL, val | O_NONBLOCK) != -1) {
			r = connect(m_connfd, &srv, addrlen);
		}
	}

	return r;
}

bool CHttpSocket::CheckConnectError(void)
{
	int s = 1;
	socklen_t len = sizeof(s);

	if (getsockopt(m_connfd, SOL_SOCKET, SO_ERROR, (void *) &s, &len) == -1) {
		return false;
	} else {
		if (s != 0) {
			cout << pthread_self() << ": getsockopt for SO_ERROR failed." << endl;
			return false;
		}
	}

	return true;
}

const int& CHttpSocket::GetConnectFd(void) const
{
	return m_connfd;
}

const int& CHttpSocket::GetEpollFd(void) const
{
	return m_epollfd;
}

const string& CHttpSocket::GetReqHeader(void) const
{
	return m_req;
}

const int& CHttpSocket::GetTimeout(void) const
{
	return m_timeout;
}

const int& CHttpSocket::GetLoop(void) const
{
	return m_loop;
}

