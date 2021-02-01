package jwt

import (
	"net/http"
)

type MockHttpWriter struct {
	header         map[string][]string
	bodyListener   func([]byte)
	headerListener func(int)
}

func (w MockHttpWriter) Write(bytes []byte) (int, error) {
	w.bodyListener(bytes)
	return 0, nil
}

func (w MockHttpWriter) WriteHeader(statusCode int) {
	w.headerListener(statusCode)
}

func (w MockHttpWriter) Header() http.Header {
	return w.header
}

type mockHttpHandler struct {
	listen func(r http.Request)
}

func newMockHttpHandler(listen func(h http.Request)) mockHttpHandler {
	return mockHttpHandler{
		listen: listen,
	}
}
func (m mockHttpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.listen(*r)
}

func newMockWriter(header func(int), body func([]byte)) MockHttpWriter {
	result := MockHttpWriter{
		header:         make(map[string][]string),
		headerListener: header,
		bodyListener:   body,
	}
	return result
}
