#include "http_socket.h"

pthread_mutex_t CHttpSocket::s_mutex = PTHREAD_MUTEX_INITIALIZER;
const int CHttpSocket::s_bufsize = 2048;

CHttpSocket::CHttpSocket(const string& uuid, const string& host, const unsigned short port,
	const string& uri, const int worker, const int loop, const int timeout)
{
	Initialize(host, port, uri, worker, loop, timeout);

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

void CHttpSocket::StartWork(void)
{
	int ret;

	if (!m_inited) {
		return;
	}

	m_tid = new pthread_t[m_worker]();
	if (!m_tid) {
		cout << pthread_self() << ": new tid array failed" << endl;
		return;
	}

	NonBlockConnect();
	if (m_run) {
		signal(SIGPIPE, SIG_IGN);
		FormatRequestHeader();
		for (int i = 0; i < m_worker; ++i) {
			ret = pthread_create(&m_tid[i], NULL, CHttpSocket::DoWork, (void *)this);
			if (ret != 0) {
				cout << pthread_self() << ": create thread failed:" << strerror(errno) << endl;
				m_run = false;
				return;
			}

			cout << m_tid[i] << " is running" << endl;
		}
	}

	return;
}

CHttpSocket::response_state CHttpSocket::CheckResponse(const string& buffer)
{
	string::size_type pos = 0;
	string size;
	stringstream ss;
	CHttpSocket::response_state s = RESPONSE_START;
	size_t body_size;

	if (buffer.empty()) {
		return (m_hdrend > 0) ? RESPONSE_START : RESPONSE_HEADER;
	}

	for ( ;; ) {
		if (m_hdrend > 0) {
			pos = buffer.rfind("Content-Length:", m_hdrend);

			if (pos != string::npos) {
				/* Content-Length */
				size.clear();

				pos += string("Content-Length:").size();
				while (buffer[pos] == ' ') {
					pos++;
				}

				while (buffer[pos] != '\r' && buffer[pos + 1] != '\n') {
					size += buffer[pos];
					pos++;
				}

				ss << size;
				ss >> body_size;

				if (buffer.size() - (m_hdrend + 4) <= body_size) {
					s = RESPONSE_DONE;
				} else {
					s = RESPONSE_HEADER;
				}
			} else {
				/* Transfer-Encoding */
				pos = buffer.rfind("Transfer-Encoding:", m_hdrend);

				if (pos == string::npos) {
					m_hdrend = 0;
					s = RESPONSE_INVALID;
					break;
				} else {
					pos = buffer.find("0\r\n", m_hdrend);
					if (pos != string::npos) {
						s = RESPONSE_DONE;
					} else {
						s = RESPONSE_HEADER;
					}
				}
			}

			break;
		} else {
			pos = buffer.find("\r\n\r\n");

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
					   "nginx, versions 1.2.6, 1.8.1 and 1.9.12 were tested on 2016"
					   "-10-10-15.%0D%0A";
	stringstream s;
	string size, req;
	ssize_t all, r = 0, delta = 0;
	int n;
	char buffer[s_bufsize];
	struct epoll_event events[2];
	int count = 0;

	CHttpSocket* obj = (CHttpSocket*) arg;
	const string& reqh = obj->GetConnectionReqHeader();

	s << str.size();
	s >> size;
	req = reqh + size + "\r\n\r\n";
	req += str;
	all = req.size();

	for ( ;; ) {
		obj->MutexLock();
		if (obj->IsLoopDone() || !obj->GetRunState()) {
			break;
		}

		const int& connfd = obj->GetConnectionFd();
		const int& epollfd = obj->GetEpollFd();
		const int& timeout = obj->GetTimeout();
		struct epoll_event& ev = obj->GetWorkEpollEvent();

		if (ev.events & EPOLLIN) {
			ev.events &= ~EPOLLIN;
			ev.events |= EPOLLOUT;

			n = epoll_ctl(epollfd, EPOLL_CTL_MOD, connfd, &ev);
			if (n == -1) {
				cout << pthread_self() << ": 1>error: " << strerror(errno) << endl;
				goto failed;
			}
		} else {
			ev.events = EPOLLOUT | EPOLLET;
			ev.data.fd = connfd;

			n = epoll_ctl(epollfd, EPOLL_CTL_ADD, connfd, &ev);
			if (n == -1) {
				cout << pthread_self() << ": 2>error: " << strerror(errno) << endl;
				goto failed;
			}
		}

		while (delta < all) {
			n = epoll_wait(epollfd, events, 2, timeout);
			if (n == -1) {
				if (errno != EINTR) {
					cout << pthread_self() << ": 3>error: " << strerror(errno) << endl;
					goto failed;
				}
			} else if (n > 0) {
				if (events[0].data.fd == connfd) {
					r = send(connfd, req.c_str() + delta, req.size() - delta, 0);
					if (r == -1) {
						if (errno != EINTR && errno != EAGAIN) {
							cout << pthread_self() << ": 4>error: " << strerror(errno) << endl;
							goto failed;
						}
					} else {
						delta += r;
					}
				}
			} else {
				cout << pthread_self() << ": epoll_wait timeout in send" << endl;
			}
		}

		ev.events &= ~EPOLLOUT;
		ev.events |= EPOLLIN;
		n = epoll_ctl(epollfd, EPOLL_CTL_MOD, connfd, &ev);
		if (n == -1) {
			cout << pthread_self() << ": 5>error: " << strerror(errno) << endl;
			goto failed;
		}

		memset(buffer, 0, s_bufsize);
		delta = 0;

		for ( ;; ) {
			n = epoll_wait(epollfd, events, 2 , timeout);
			if (n == -1) {
				if (errno != EINTR) {
					cout << pthread_self() << ": 6>error: " << strerror(errno) << endl;
					goto failed;
				}
			} else if (n > 0) {
				if (events[0].data.fd == connfd) {
					for ( ;; ) {
						r = recv(connfd, buffer + delta, s_bufsize - delta, 0);
						if (r == -1) {
							if (errno != EAGAIN) {
								cout << pthread_self() << ": 7>error: " << strerror(errno) << endl;
								goto failed;
							} else {
								break;
							}
						} else if (r == 0) {
							delta = 0;
							cout << pthread_self() << ": peer closed the connection" << endl;
							obj->ReInitialize();
							obj->NonBlockConnect();
							goto retry;
						} else {
							delta += r;
							CHttpSocket::response_state s = obj->CheckResponse(string(buffer));
							if (s == CHttpSocket::RESPONSE_DONE) {
								delta = 0;

								if (++count > 20) {
									obj->ReInitialize();
									obj->NonBlockConnect();
									count = 0;
								}

								goto done;
							}
						}
					}
				}
			} else {
				cout << pthread_self() << ": epoll timeout in recv" << endl;
			}
		}

done:
		obj->DecreaseLoop();

		if (obj->IsLoopDone()) {
			break;
		} else {
retry:
			obj->MutexUnlock();
		}
	}

	obj->MutexUnlock();
	return NULL;

failed:
	obj->DecreaseLoop();
	obj->MutexUnlock();
	return NULL;
}

void CHttpSocket::Initialize(const string& host, const unsigned short port, const string& uri,
	const int worker, const int loop, const int timeout)
{
	m_connfd = -1;
	m_hdrend = 0;
	m_run = false;
	m_inited = false;
	m_tid = NULL;

	m_host = host.empty() ? "localhost" : host;
	stringstream s;
	s << port;
	s >> m_port;
	m_uri = uri.empty() ? "/" : uri;
	m_loop = (loop <= 0) ? 50 : loop;
	m_worker = (worker <= 0) ? 1 : worker;
	m_timeout = (timeout <= 0) ? 50 : timeout;

	m_epollfd = epoll_create(10);
	if (m_epollfd == -1) {
		Finalize();
	}
}

void CHttpSocket::ReInitialize(void)
{
	epoll_ctl(m_epollfd, EPOLL_CTL_DEL, m_connfd, NULL);
	close(m_connfd);
	m_connfd = -1;
}

void CHttpSocket::Finalize(void)
{
	if (m_tid) {
		for (int i = 0; i < m_worker; ++i) {
			if (m_tid[i] != 0) {
				pthread_join(m_tid[i], NULL);
			}
		}

		delete [] m_tid;
		m_tid = NULL;
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

	m_run = false;
	m_inited = false;
	m_worker = 0;
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

void CHttpSocket::NonBlockConnect(void)
{
	int r, val;
	struct sockaddr srv;
	size_t addrlen;
	int retry = 3;
	int s = 1;
	socklen_t len = sizeof(s);
	struct epoll_event events[2];

	bool ret = ResolveServer(&srv, &addrlen);
	if (ret) {
		val = fcntl(m_connfd, F_GETFL, 0);
		if (fcntl(m_connfd, F_SETFL, val | O_NONBLOCK) == -1) {
			goto failed;
		}

		r = connect(m_connfd, &srv, addrlen);
		if (r == -1) {
			if (errno != EINPROGRESS) {
				goto failed;
			} else {
				m_connev.events = EPOLLOUT | EPOLLET;
				m_connev.data.fd = m_connfd;

				r = epoll_ctl(m_epollfd, EPOLL_CTL_ADD, m_connfd, &m_connev);
				if (r == -1) {
					goto failed;
				}

				while (retry-- > 0) {
					r = epoll_wait(m_epollfd, events, 2, m_timeout);
					if (r == -1) {
						if (errno != EINTR) {
							goto failed;
						}
					} else if (r > 0) {
						if (events[0].data.fd == m_connfd) {
							if (getsockopt(m_connfd, SOL_SOCKET, SO_ERROR, (void *) &s, &len) == -1) {
								goto failed;
							} else {
								if (s != 0) {
									cout << pthread_self() << ": getsockopt for SO_ERROR failed" << endl;
									goto failed;
								} else {
									epoll_ctl(m_epollfd, EPOLL_CTL_DEL, m_connfd, NULL);
									m_workev.events = 0;
									m_workev.data.fd = m_connfd;
									m_run = true;
									return;
								}
							}
						}
					} else {
						cout << pthread_self() << ": epoll_wait timeout in connect" << endl;
					}
				}

				if (retry == 0) {
					epoll_ctl(m_epollfd, EPOLL_CTL_DEL, m_connfd, NULL);
					goto failed;
				}
			}
		}
	} else {
		goto failed;
	}

	return;

failed:
	m_run = false;
}

const int& CHttpSocket::GetConnectionFd(void) const
{
	return m_connfd;
}

const int& CHttpSocket::GetEpollFd(void) const
{
	return m_epollfd;
}

struct epoll_event& CHttpSocket::GetWorkEpollEvent(void)
{
	return m_workev;
}

const string& CHttpSocket::GetConnectionReqHeader(void) const
{
	return m_req;
}

const int& CHttpSocket::GetTimeout(void) const
{
	return m_timeout;
}

const bool& CHttpSocket::GetRunState(void) const
{
	return m_run;
}

bool CHttpSocket::IsLoopDone(void)
{
	return m_loop <= 0;
}

void CHttpSocket::DecreaseLoop(void)
{
	--m_loop;
}

void CHttpSocket::MutexLock(void)
{
	pthread_mutex_lock(&s_mutex);
}

void CHttpSocket::MutexUnlock(void)
{
	pthread_mutex_unlock(&s_mutex);
}

