package saml

import (
	"encoding/xml"
	"net"
	"time"

	"github.com/amdonov/xmlsig"
)

type Subject struct {
	XMLName             xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Subject"`
	NameID              *NameID
	SubjectConfirmation *SubjectConfirmation
}

type Issuer struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

type Conditions struct {
	XMLName             xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Conditions"`
	NotBefore           time.Time `xml:",attr"`
	NotOnOrAfter        time.Time `xml:",attr"`
	AudienceRestriction *AudienceRestriction
}

type SubjectLocality struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectLocality"`
	Address net.IP   `xml:",attr"`
}

type AuthnContext struct {
	XMLName              xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContext"`
	AuthnContextClassRef string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnContextClassRef"`
}

type AuthnStatement struct {
	XMLName         xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion AuthnStatement"`
	AuthnInstant    time.Time `xml:",attr"`
	SessionIndex    string    `xml:",attr"`
	SubjectLocality *SubjectLocality
	AuthnContext    *AuthnContext
}

type AttributeValue struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	Value   string   `xml:",chardata"`
}

type Attribute struct {
	XMLName        xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion Attribute"`
	FriendlyName   string   `xml:",attr"`
	Name           string   `xml:",attr"`
	NameFormat     string   `xml:",attr"`
	AttributeValue []AttributeValue
}

type AttributeStatement struct {
	XMLName   xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeStatement"`
	Attribute []Attribute
}

type NameID struct {
	XMLName         xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format          string   `xml:",attr"`
	NameQualifier   string   `xml:",attr"`
	SPNameQualifier string   `xml:",attr"`
	Value           string   `xml:",chardata"`
}

type SubjectConfirmation struct {
	XMLName                 xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmation"`
	Method                  string   `xml:",attr"`
	SubjectConfirmationData *SubjectConfirmationData
}

type SubjectConfirmationData struct {
	XMLName      xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion SubjectConfirmationData"`
	Address      net.IP    `xml:",attr"`
	InResponseTo string    `xml:",attr"`
	NotOnOrAfter time.Time `xml:",attr"`
	Recipient    string    `xml:",attr"`
}

type AudienceRestriction struct {
	XMLName  xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion AudienceRestriction"`
	Audience string   `xml:"urn:oasis:names:tc:SAML:2.0:assertion Audience"`
}

type Assertion struct {
	XMLName            xml.Name  `xml:"urn:oasis:names:tc:SAML:2.0:assertion Assertion"`
	ID                 string    `xml:",attr"`
	Version            string    `xml:",attr"`
	IssueInstant       time.Time `xml:",attr"`
	Issuer             *Issuer
	Signature          *xmlsig.Signature
	Subject            *Subject
	Conditions         *Conditions
	AuthnStatement     *AuthnStatement
	AttributeStatement *AttributeStatement
}
