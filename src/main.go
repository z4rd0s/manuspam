package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"unicode"

	"os"
	"strings"

	"github.com/mcnijman/go-emailaddress"
)

const inlyseBanner = `

██╗███╗   ██╗██╗  ██╗   ██╗███████╗███████╗     ██████╗██╗     ██╗
██║████╗  ██║██║  ╚██╗ ██╔╝██╔════╝██╔════╝    ██╔════╝██║     ██║
██║██╔██╗ ██║██║   ╚████╔╝ ███████╗█████╗█████╗██║     ██║     ██║
██║██║╚██╗██║██║    ╚██╔╝  ╚════██║██╔══╝╚════╝██║     ██║     ██║
██║██║ ╚████║███████╗██║   ███████║███████╗    ╚██████╗███████╗██║

inlyse MALWAREAI-CLI: Malware Detection using Artificial Intelligence.`

const (
	AppName     = "inlyse-mailparser-cli"
	AppVersion  = "0.0.1"
	initCmdHelp = "Extract Features from eml files"
)

type Featureset struct {
	Content_Transfer_Encoding_field bool
	Content_Type                    string

	Received_SPF string
	DKIM         string

	X_Mailer_exists bool

	From_count_addresses               int
	From_header_missing                []bool
	From_has_title                     []bool
	From_dn_exists                     []bool
	From_DN_whitespaces                []int
	FROM_DOMAIN_EQUAL_MESSAGEID_DOMAIN []bool
	FROM_DOMAIN_EQUAL_TO_DOMAIN        []bool
	From_DN_has_nonascii               []bool
	From_address_equal_to_address      []bool
	From_address_equal_reply_address   []bool
	From_DN_count_special_chars        []int

	Reply_TO_empty        bool
	Reply_TO_questionmark bool

	To_count_addresses   int
	To_undisclosed       bool
	To_empty             bool
	BCC_count_recepients int

	subject_special_chars bool

	total_emailadresses int
}

func _contains(elems []string, v string) bool {
	for _, s := range elems {
		if v == s {
			return true
		}
	}
	return false
}

func _parse_emailadress(address string) (*emailaddress.EmailAddress, error) {
	email, err := emailaddress.Parse(address)
	if err != nil {
		fmt.Println("can't parse mailadress")
	}
	return email, err
}

func _isNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return true
		}
	}
	return false
}

/** From Address features loop for extracting the following features:
* From_count_addresses: int
* From_header_missing or emtpy: []bool
* From_Title (mr. mrs. prof. dr.): []bool
* From_has_dn: []bool
**/
//func from_loop(email *Email, featureset *Features) (featureset *Features, err error) {
func from_features_loop(email *Email, Featureset *Featureset) {
	var _from_cache []string
	if email.From_domain == nil {
		if email.ReturnPath != nil {
			if len(email.From) == 0 {
				email.From = append(email.From, email.ReturnPath)
			} else {
				email.From[0] = email.ReturnPath
			}
		} else {
			return
		}
	}
	for _, from := range email.From {
		sender_address, err := _parse_emailadress(from.Address)
		if err != nil {
			fmt.Println("cant parse from email", err)
			return
		}
		/* count from addresses */
		if !_contains(_from_cache, from.Address) {
			_from_cache = append(_from_cache, from.Address)
			Featureset.From_count_addresses += 1
		}

		/** check if from header exists**/
		Featureset.From_header_missing = append(
			Featureset.From_header_missing,
			len(from.Address) == 0)

		/* check if from dn has title */
		name := strings.ToLower(from.Name)
		Featureset.From_has_title = append(
			Featureset.From_has_title,
			(strings.Contains(name, "mr.") ||
				strings.Contains(name, "mr.") ||
				strings.Contains(name, "prof.") ||
				strings.Contains(name, "dr.")))

		/* check if dn is empty or not existent */
		Featureset.From_dn_exists = append(
			Featureset.From_dn_exists,
			name != "" || name != " " || len(name) != 0)

		/* count whitespaces */
		Featureset.From_DN_whitespaces = append(
			Featureset.From_DN_whitespaces, strings.Count(name, " "))

		/* DN count special chars */
		count_special_chars := strings.Count("?", from.String()) +
			strings.Count(from.String(), "!") +
			strings.Count(from.String(), "<") +
			strings.Count(from.String(), ">")
		Featureset.From_DN_count_special_chars = append(
			Featureset.From_DN_count_special_chars, count_special_chars)

		/* from domain equal to messageID domain */
		mid, err := _parse_emailadress(email.MessageID)
		if err != nil {
			Featureset.FROM_DOMAIN_EQUAL_MESSAGEID_DOMAIN = append(
				Featureset.FROM_DOMAIN_EQUAL_MESSAGEID_DOMAIN,
				false)
		} else {
			Featureset.FROM_DOMAIN_EQUAL_MESSAGEID_DOMAIN = append(
				Featureset.FROM_DOMAIN_EQUAL_MESSAGEID_DOMAIN,
				mid.Domain == sender_address.Domain)
		}

		/* from Domains equals to domain */
		for _, to := range email.To {
			to_address, err := _parse_emailadress(to.Address)
			if err != nil {
				fmt.Println("cant parse to address", err)
			} else {
				Featureset.FROM_DOMAIN_EQUAL_TO_DOMAIN = append(
					Featureset.FROM_DOMAIN_EQUAL_TO_DOMAIN,
					sender_address.Domain == to_address.Domain)
			}
		}

		/* check if from DN contains nonascii characters */
		Featureset.From_DN_has_nonascii = append(
			Featureset.From_DN_has_nonascii, _isNonASCII(from.Name))

		/* check if from address equals replyto address */
		var reply_address string
		if email.ReplyTo != nil {
			reply_address = email.ReplyTo.Address
		} else if email.ReturnPath != nil {
			reply_address = email.ReturnPath.Address
		} else {
			reply_address = from.Address
		}
		Featureset.From_address_equal_reply_address = append(
			Featureset.From_address_equal_reply_address,
			strings.Compare(from.Address, reply_address) == 0)

		/* check if from address equals replyto address */
		for _, to := range email.To {
			Featureset.From_address_equal_to_address = append(
				Featureset.From_address_equal_to_address,
				strings.Compare(from.Address, to.Address) == 0)
		}
	}
}

func reply_to_loop(email *Email, featureset *Featureset) {
	if email.ReplyTo == nil {
		featureset.Reply_TO_empty = true
	} else {
		featureset.Reply_TO_empty = false

		/* check if reply to contains special chars */
		if strings.Contains(email.ReplyTo.String(), "?") {
			featureset.Reply_TO_questionmark = true
		} else {
			featureset.Reply_TO_questionmark = false
		}
	}
}

func get_spf(email *Email, Featureset *Featureset) {
	var spf string
	received_spf_string := strings.ToLower(email.Received_SPF)

	if strings.HasPrefix(received_spf_string, "pass") {
		spf = "pass"
	} else if strings.HasPrefix(received_spf_string, "fail") {
		spf = "fail"
	} else if strings.HasPrefix(received_spf_string, "bad") {
		spf = "bad"
	} else if strings.HasPrefix(received_spf_string, "softfail") {
		spf = "softfail"
	} else {
		spf = "ok"
	}
	Featureset.Received_SPF = spf
}

func get_dkim(email *Email, Featureset *Featureset) {
	if val, exist := email.Header["Authentication-Results"]; exist {
		dkim := strings.ToLower(val[0])
		if strings.Contains(dkim, "dkim=fail") ||
			strings.Contains(dkim, "dkim=softfail") {
			Featureset.DKIM = "fail"
		} else if strings.Contains(dkim, "dkim=pass") {
			Featureset.DKIM = "pass"
		} else {
			Featureset.DKIM = "unknown"
		}
	} else {
		Featureset.DKIM = "non-existent"
	}
}

func bcc_count_recepients(email *Email, Featureset *Featureset) {
	Featureset.BCC_count_recepients = len(email.Bcc)
}

func get_content_transfer_encoding(email *Email, Featureset *Featureset) {
	if email.Content_Transfer_Encoding == "" {
		Featureset.Content_Transfer_Encoding_field = false
	} else {
		Featureset.Content_Transfer_Encoding_field = true
	}
	Featureset.Content_Type = email.ContentTypeParsed
}

func get_subject_features(email *Email, Featureset *Featureset) {
	if strings.Contains(email.Subject, "?") ||
		strings.Contains(email.Subject, "=") {
		Featureset.subject_special_chars = true
	} else {
		Featureset.subject_special_chars = true
	}
}

func X_Mailer_Exists(email *Email, Featureset *Featureset) {
	if email.XMailer != "" {
		Featureset.X_Mailer_exists = true
	} else {
		Featureset.X_Mailer_exists = false
	}
}

func to_features_loop(email *Email, Featureset *Featureset) {
	Featureset.To_count_addresses = len(email.To)

	to_count_special_chars := 0
	for _, To := range email.To {
		if len(email.To) == 1 && strings.Contains(strings.ToLower(To.String()), "undisclosed") {
			Featureset.To_undisclosed = true
		}
		to_count_special_chars += strings.Count(To.String(), "<")
		to_count_special_chars += strings.Count(To.String(), ">")
	}
}

func get_features(email *Email) *Featureset {
	featureset := Featureset{}
	from_features_loop(email, &featureset)
	get_spf(email, &featureset)
	get_dkim(email, &featureset)
	bcc_count_recepients(email, &featureset)
	get_content_transfer_encoding(email, &featureset)
	reply_to_loop(email, &featureset)
	get_subject_features(email, &featureset)
	X_Mailer_Exists(email, &featureset)
	to_features_loop(email, &featureset)

	featureset.total_emailadresses = featureset.From_count_addresses +
		featureset.BCC_count_recepients +
		featureset.To_count_addresses
	//from Domain equals to domain
	//_, to_email := get_email_dn(email.From)
	//_, to_domain := split_email(to_email)
	//features.FROM_DOMAIN_EQUAL_TO_DOMAIN = domains_equal(email.From_Domain, to_domain)

	//if strings.Compare(email.From_Email, to_address) == 0 {
	//	features.From_address_equal_to_address = true
	//} else {
	//	features.From_address_equal_to_address = false
	//}
	return &featureset
}

func main() {
	fmt.Println(inlyseBanner)

	var path []string
	path = os.Args[1:]
	if len(path) == 0 {
		path = append(path, "../../dataset/spam/1049222514.2172_149.txt")
	}

	pathinfo, err := os.Stat(path[0])
	if err != nil {
		log.Fatalf("Path does not exists.")
	}

	files := []string{}

	if pathinfo.IsDir() {
		data, err := ioutil.ReadDir(path[0])
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range data {
			files = append(files, path[0]+f.Name())
		}
	} else {
		files = append(files, path[0])
	}

	for _, path := range files {
		fmt.Println(path)
		file, err := os.Open(path)
		if err != nil {
			log.Fatal(err.Error())
		}

		email, err := Parse(bufio.NewReader(file))
		if err != nil {
			fmt.Println("cant parse email", err)
		} else {

			features := get_features(&email)

			featuresJSON, err := json.MarshalIndent(&features, "", "  ")
			if err != nil {
				log.Fatalf(err.Error(), featuresJSON)
			}
			//fmt.Printf("email feature extraction %s\n", string(featuresJSON))
			_ = ioutil.WriteFile(string(file.Name())+".features.json", featuresJSON, 0644)
		}
	}
}
