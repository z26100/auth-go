package auth

import (
	"encoding/json"
	log "github.com/z26100/log-go"
	"io/ioutil"
	"net/http"
)

type PublicKeyProvider interface {
	Get() ([]byte, error)
}

type FilePublicKeyProvider struct {
	filename  string
	publicKey []byte
}

type WebsitePublicKeyProvider struct {
	url       string
	publicKey []byte
	adapter   Adapter
}

func NewFilePublicKeyProvider(filename string) *FilePublicKeyProvider {
	return &FilePublicKeyProvider{
		filename: filename,
	}
}

func (p *FilePublicKeyProvider) Get() ([]byte, error) {
	var err error
	if p.publicKey == nil {
		p.publicKey, err = p.ReadPublicKeyAsPEMFromFile(p.filename)
	}
	return p.publicKey, err
}

func (p FilePublicKeyProvider) ReadPublicKeyAsPEMFromFile(filename string) ([]byte, error) {
	pem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return pem, err
}

func NewWebsitePublicKeyProvider(url string, adapter Adapter) *WebsitePublicKeyProvider {
	return &WebsitePublicKeyProvider{
		url:     url,
		adapter: adapter,
	}
}

func (p *WebsitePublicKeyProvider) Get() ([]byte, error) {
	var err error
	if p.publicKey == nil {
		p.publicKey, err = p.readPublicKeyFromWebsite()
	}
	return p.publicKey, err
}

func (p *WebsitePublicKeyProvider) readPublicKeyFromWebsite() ([]byte, error) {
	log.Debugf("reading public key from %s", p.url)
	resp, err := http.Get(p.url)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	var certs interface{}
	err = json.Unmarshal(body, &certs)
	if err != nil {
		return nil, err
	}
	publicKey, err := p.adapter.Get(certs)
	return getPublicKeyAsPEM(publicKey), err
}
