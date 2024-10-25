package opennebula

import (
	"encoding/xml"
	"os"
)

type AuthData struct {
	XMLName  xml.Name `xml:"AUTHN"`
	Username string   `xml:"USERNAME"`
	Password string   `xml:"PASSWORD"`
	Secret   string   `xml:"SECRET"`
}

func FetchAuthData() (*AuthData, error) {
	var nData AuthData
	xmlDec := xml.NewDecoder(os.Stdin)
	err := xmlDec.Decode(&nData)
	if err != nil {
		return nil, err
	}
	return &nData, nil
}
