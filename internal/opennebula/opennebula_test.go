// opennebula_test.go

package opennebula

import (
	"fmt"
	"log"
	"os"
	"reflect"
	"testing"
)

func TestFetchAuthData(t *testing.T) {
	xmlData := `<AUTHN><USERNAME>mohammadm</USERNAME><PASSWORD>-</PASSWORD><SECRET>m.m.cybermin24242</SECRET></AUTHN>`
	// Creating a temp file to mimic the stdin
	tmpFile, err := os.CreateTemp("/tmp/", "test_file")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name()) // Clean up the file after test

	if _, err := tmpFile.WriteString(xmlData); err != nil {
		log.Fatal(err)
	}
	if _, err := tmpFile.Seek(0, 0); err != nil { // reseting the offset of the file to where 0 on each read and write
		log.Fatal(err)
	}

	expectedData := &AuthData{
		Username: "mohammadm",
		Password: "-",
		Secret:   "m.m.cybermin24242",
	}

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }() // Restore original Stdin

	os.Stdin = tmpFile // Passing the file Content to stdin
	// Call FetchAuthData to parse the XML
	authData, err := FetchAuthData()
	if err != nil {
		fmt.Println(authData)
		t.Fatalf("Expected no error, got %v", err)
	}
	// Validate that the output matches the expected structure
	if !reflect.DeepEqual(authData, expectedData) {
		t.Errorf("Expected %+v, got %+v", expectedData, authData)
	}
}
