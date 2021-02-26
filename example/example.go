//
// Copyright (c) 2021 Cisco Systems, Inc and its affiliates
// All Rights reserved
//
package main

import (
	msxsecurity "github.com/CiscoDevNet/go-msx-security"
	"fmt"
	"log"
	"net/http"
)
// READ_HELLO will represent the permission required to access the application end points
// In this example we'll use the msx VIEW_SERVICES permission as our stand in as it is one of the default set
// Custom permissions can be added to MSX to suite whatever needs the application has
const READ_HELLO = "VIEW_SERVICES"

// The MsxSecurity global will represent the MsxSecurity validator provided by msx-security
var MsxSecurity = &msxsecurity.MsxSecurity{}

//EnsureAuth will wrap http handle funcs that require auth
type EnsureAuth struct {
	permission string
	handler http.HandlerFunc
}
// ServeHTTP will perform the auth on behalf of the embedded handlerfunc
func (ea *EnsureAuth) ServeHTTP(w http.ResponseWriter, r *http.Request){
	permitted, _ := MsxSecurity.HasPermission(r,ea.permission)
	if permitted {
		ea.handler(w,r)
	}else{
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w,"Access denied")
	}
}

//NewEnsureAuth will be used to generate an auth wrapper
func NewEnsureAuth(handlerToWrap http.HandlerFunc, permission string) *EnsureAuth{
	return &EnsureAuth{
		permission: permission,
		handler:    handlerToWrap,
	}
}


// In this handler we will use the msxsecurity object directly which is the simplest pattern
// although, it is not suitable for larger applications due to repetitive code requirements
func hellowithauth(w http.ResponseWriter, r *http.Request) {
	permitted, _ := MsxSecurity.HasPermission(r,READ_HELLO)
	if permitted{
		fmt.Fprint(w, "Hello from myservice! You were authorized.")
	}else{
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w,"Access denied")
	}
}

// In this handler we will rely on a wrapping handler to provide access restrictions
func hello(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "Hello from myservice! You were authorized.")
}

func main() {
	// Create a new default security config.
	c := msxsecurity.DefaultMsxSecurityConfig()
	// Customize the default to represent your actual environment
	c.SsoURL = "https://trn6-demo2.ciscovms.com/idm"
	c.ClientID = "my-private-security-client"
	c.ClientSecret = ""

	// Note:  In production you would want to customize your TLS config and enable caching.
	// Now setup our MsxSecurity object
	MsxSecurity = msxsecurity.NewMsxSecurity(c)
	//Add our handler with built in auth
	http.HandleFunc("/hellowithauth",hellowithauth)

	//Add our Wrapped function
	http.Handle("/hellowrapped", NewEnsureAuth(hello,READ_HELLO))

	//Add the basic Hello to show an unauthorized example
	http.HandleFunc("/hello", hello)

	log.Fatal(http.ListenAndServe(":8080",nil))
}