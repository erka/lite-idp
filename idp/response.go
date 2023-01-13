// Copyright © 2017 Aaron Donovan <amdonov@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package idp

import (
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"time"

	"github.com/amdonov/lite-idp/model"
	"github.com/amdonov/lite-idp/saml"
	"github.com/google/uuid"
	"github.com/spf13/viper"
	"google.golang.org/protobuf/proto"
)

func (i *IDP) respond(authRequest *model.AuthnRequest, user *model.User,
	w http.ResponseWriter, r *http.Request) error {
	// Save user information and set session cookie
	data, err := proto.Marshal(user)
	if err != nil {
		return err
	}
	session := uuid.New().String()
	err = i.UserCache.Set(session, data)
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     i.cookieName,
		Path:     "/",
		Value:    session,
		Secure:   true,
		HttpOnly: true,
	})
	switch authRequest.ProtocolBinding {
	case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact":
		return i.sendArtifactResponse(authRequest, user, w, r)
	case "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST":
		return i.sendPostResponse(authRequest, user, w, r)
	case "urn:oasis:names:tc:SAML:2.0:bindings:PAOS":
		return i.sendECPResponse(authRequest, user, w, r)
	default:
		return errors.New("unsupported protocol binding")
	}
}

func (i *IDP) makeAuthnResponse(request *model.AuthnRequest, user *model.User) *saml.Response {
	now := time.Now().UTC()
	fiveFromNow := now.Add(5 * time.Minute)
	resp := i.makeResponse(request.ID, request.Issuer, request.Audience, user)
	// Add subject confirmation data and authentication statement
	resp.Assertion.AuthnStatement = &saml.AuthnStatement{
		AuthnInstant: now,
		SessionIndex: saml.NewID(),
		SubjectLocality: &saml.SubjectLocality{
			DNSName: i.serverName,
		},
		AuthnContext: &saml.AuthnContext{
			AuthnContextClassRef: user.Context,
		},
	}
	resp.Assertion.Subject.SubjectConfirmation = &saml.SubjectConfirmation{
		Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
		SubjectConfirmationData: &saml.SubjectConfirmationData{
			Address:      net.ParseIP(user.IP),
			InResponseTo: request.ID,
			Recipient:    request.AssertionConsumerServiceURL,
			NotOnOrAfter: fiveFromNow,
		},
	}
	return resp
}

func (i *IDP) makeResponse(id, issuer, audience string, user *model.User) *saml.Response {
	now := time.Now().UTC()
	fiveFromNow := now.Add(5 * time.Minute)

	var mapping map[string]string
	var subject string

	if sp, ok := i.sps[issuer]; ok {
		subject = sp.Subject
		mapping = sp.Mapping
	}

	attributes := user.Attributes
	subjectValue := user.Name
	attributeStatement := &saml.AttributeStatement{}
	if user.Attributes != nil {
		for _, val := range attributes {
			if val.Name == subject && len(val.Value) > 0 {
				subjectValue = val.Value[0]
			}

			if mappedAttributeName, ok := mapping[val.Name]; ok {
				attVals := make([]saml.AttributeValue, len(val.Value))
				for i := range val.Value {
					attVals[i] = saml.AttributeValue{Value: val.Value[i]}
				}
				att := saml.Attribute{
					FriendlyName:   mappedAttributeName,
					Name:           mappedAttributeName,
					NameFormat:     viper.GetString("saml-attribute-name-format"),
					AttributeValue: attVals,
				}
				attributeStatement.Attribute = append(attributeStatement.Attribute, att)
			}
		}
	}

	s := &saml.Response{
		StatusResponseType: saml.StatusResponseType{
			Version:      "2.0",
			ID:           saml.NewID(),
			IssueInstant: now,
			Status: &saml.Status{
				StatusCode: saml.StatusCode{
					Value: "urn:oasis:names:tc:SAML:2.0:status:Success",
				},
			},
			InResponseTo: id,
			Issuer:       saml.NewIssuer(i.entityID),
		},
		Assertion: &saml.Assertion{
			ID:           saml.NewID(),
			IssueInstant: now,
			Issuer:       saml.NewIssuer(i.entityID),
			Version:      "2.0",
			Subject: &saml.Subject{
				NameID: &saml.NameID{
					Format:          user.Format,
					NameQualifier:   i.entityID,
					SPNameQualifier: issuer,
					Value:           subjectValue,
				},
				SubjectConfirmation: &saml.SubjectConfirmation{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches",
				},
			},
			AttributeStatement: attributeStatement,
			Conditions: &saml.Conditions{
				NotOnOrAfter: fiveFromNow,
				NotBefore:    now,
				AudienceRestriction: &saml.AudienceRestriction{
					Audience: audience,
				},
			},
		},
	}
	return s
}

func getArtifact(entityID string) string {
	// The artifact isn't just a random session id. It's a base64-encoded byte array
	// that's 44 bytes in length. The first two bytes must be 04 for SAML 2. The second
	// two bytes are the index of the artifact resolution endpoint in the IdP metadata. Something like 02
	// The next 20 bytes are the sha1 hash of the IdP's entity ID
	// The last 20 bytes are unique to the request
	artifact := make([]byte, 44)
	// Use SAML 2
	artifact[1] = byte(4)
	// Index 1
	artifact[3] = byte(1)
	// Hash of entity ID
	source := sha1.Sum([]byte(entityID))
	for i := 4; i < 24; i++ {
		artifact[i] = source[i-4]
	}
	// Message ID
	message := sha1.Sum([]byte(uuid.New().String()))
	for i := 24; i < 44; i++ {
		artifact[i] = message[i-24]
	}
	return base64.StdEncoding.EncodeToString(artifact)
}
