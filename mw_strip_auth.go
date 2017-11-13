package main

import (
	"net/http"
	"net/url"

	"github.com/Sirupsen/logrus"
)

type StripAuth struct {
	BaseMiddleware
}

func (sa *StripAuth) Name() string {
	return "StripAuth"
}

func (sa *StripAuth) EnabledForSpec() bool {
	return sa.Spec.StripAuthData
}

func (sa *StripAuth) ProcessRequest(w http.ResponseWriter, r *http.Request, _ interface{}) (error, int) {

	log.WithFields(logrus.Fields{
		"prefix": sa.Name(),
	}).Debugf("sa.Spec.Auth: %+v\n", sa.Spec.Auth)

	if sa.Spec.Auth.UseParam {
		if err := sa.stripFromParams(r); err != nil {

			// TODO - code review, confirm how to handle error:
			// return nil, 200 // but log msg to allow request to proceed
			// return err, 200
			return err, 500
		}

		return nil, 200
	}

	sa.stripFromHeaders(r)

	return nil, 200
}

func (sa *StripAuth) stripFromParams(r *http.Request) error {

	config := sa.Spec.Auth

	reqUrlPtr, err := url.Parse(r.URL.String())
	if err != nil {
		return err
	}

	queryStringValues := reqUrlPtr.Query()

	authParamName := config.ParamName

	if authParamName == "" {
		authParamName = config.AuthHeaderName
	}

	queryStringValues.Del(authParamName)

	reqUrlPtr.RawQuery = queryStringValues.Encode()

	r.URL, err = r.URL.Parse(reqUrlPtr.String())
	if err != nil {
		return err
	}

	return nil
}

// strips auth key from headers
func (sa *StripAuth) stripFromHeaders(r *http.Request) {

	config := sa.Spec.Auth

	authHeaderName := config.AuthHeaderName
	if authHeaderName == "" {
		authHeaderName = "Authorization"
	}

	r.Header.Del(authHeaderName)
}
