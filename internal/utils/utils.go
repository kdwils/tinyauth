package utils

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"tinyauth/internal/constants"
	"tinyauth/internal/types"

	"github.com/rs/zerolog/log"
)

// Parses a list of comma separated users in a struct
func ParseUsers(users string) (types.Users, error) {
	log.Debug().Msg("Parsing users")

	// Create a new users struct
	var usersParsed types.Users

	// Split the users by comma
	userList := strings.Split(users, ",")

	// Check if there are any users
	if len(userList) == 0 {
		return types.Users{}, errors.New("invalid user format")
	}

	// Loop through the users and split them by colon
	for _, user := range userList {
		parsed, err := ParseUser(user)

		// Check if there was an error
		if err != nil {
			return types.Users{}, err
		}

		// Append the user to the users struct
		usersParsed = append(usersParsed, parsed)
	}

	log.Debug().Msg("Parsed users")

	// Return the users struct
	return usersParsed, nil
}

// GetUpperDomainFromRequest parses a hostname and returns the upper domain.
// Respects the X-Forwarded-Host and X-Forwarded-Proto headers.
//
// sub1.sub2.domain.com -> sub2.domain.com
//
// sub2.domain.com -> domain.com
//
// domain.com -> domain.com
func GetUpperDomainFromRequest(req *http.Request) (string, error) {
	if req == nil {
		return "", errors.New("request is nil")
	}
	if req.URL == nil {
		return "", errors.New("request URL is nil")
	}

	host := req.Host
	forwardedHost := req.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" {
		host = forwardedHost
	}

	scheme := req.URL.Scheme
	forwardedProtocol := req.Header.Get("X-Forwarded-Proto")
	if forwardedProtocol != "" {
		scheme = forwardedProtocol
	}

	url := url.URL{
		Scheme: scheme,
		Host:   host,
	}

	hostname := url.Hostname()

	splitHostname := strings.Split(hostname, ".")

	// If we have 2 or fewer parts (e.g., domain.com) then return the full host instead of the upper domain
	if len(splitHostname) <= 2 {
		return hostname, nil
	}

	return strings.Join(splitHostname[1:], "."), nil
}

// Get upper domain parses a hostname and returns the upper domain (e.g. sub1.sub2.domain.com -> sub2.domain.com)
func GetUpperDomain(urlSrc string) (string, error) {
	// Make sure the url is valid
	urlParsed, err := url.Parse(urlSrc)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Split the hostname by period
	urlSplitted := strings.Split(urlParsed.Hostname(), ".")

	// Get the last part of the url
	urlFinal := strings.Join(urlSplitted[1:], ".")

	// Return the root domain
	return urlFinal, nil
}

// Reads a file and returns the contents
func ReadFile(file string) (string, error) {
	// Check if the file exists
	_, err := os.Stat(file)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Read the file
	data, err := os.ReadFile(file)

	// Check if there was an error
	if err != nil {
		return "", err
	}

	// Return the file contents
	return string(data), nil
}

// Parses a file into a comma separated list of users
func ParseFileToLine(content string) string {
	// Split the content by newline
	lines := strings.Split(content, "\n")

	// Create a list of users
	users := make([]string, 0)

	// Loop through the lines, trimming the whitespace and appending to the users list
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		users = append(users, strings.TrimSpace(line))
	}

	// Return the users as a comma separated string
	return strings.Join(users, ",")
}

// GetDomainSecrets retrieves the domain secrets from the environment variables or a file.
// The keys are the domain names and the value is the secrets.
// Secrets from file take precedence over environment variables.
func GetDomainSecrets(domains []string, file string) map[string]string {
	filesLines := make([]string, 0)
	if file != "" {
		contents, err := ReadFile(file)
		if err != nil {
			log.Error().Err(err).Msg("Failed to read domain secrets file")
			return nil
		}

		lines := strings.Split(contents, "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			log.Debug().Str("line", line).Msg("Parsing domain secrets file")
			filesLines = append(filesLines, strings.TrimSpace(line))
		}
	}

	secrets := make(map[string]string)
	for _, domain := range domains {
		// example.com -> EXAMPLE_COM
		domainKey := strings.ToUpper(strings.ReplaceAll(domain, ".", "_"))
		// EXAMPLE_COM_SECRET = "my-example-com-secret"
		domainSpecificKey := fmt.Sprintf("%s_SECRET", domainKey)

		for _, line := range filesLines {
			before, after, found := strings.Cut(line, "=")
			if !found {
				continue
			}

			if before != domainSpecificKey {
				continue
			}

			secret := trimQuotes(after)
			secrets[domain] = strings.TrimSpace(secret)
		}

		// dont overwrite the secret if it is already set by the secret file
		if secrets[domain] != "" {
			log.Debug().Str("domain", domain).Msg("Secret already set by file")
			continue
		}

		envSecret := os.Getenv(domainSpecificKey)
		if envSecret != "" {
			secrets[domain] = envSecret
		}

	}

	return secrets
}

// remove "" and ” from a line
func trimQuotes(line string) string {
	line = strings.TrimSpace(line)
	line = strings.Trim(line, "\"'")
	return line
}

// Get the secret from the config or file
func GetSecret(conf string, file string) string {
	// If neither the config or file is set, return an empty string
	if conf == "" && file == "" {
		return ""
	}

	// If the config is set, return the config (environment variable)
	if conf != "" {
		return conf
	}

	// If the file is set, read the file
	contents, err := ReadFile(file)
	// Check if there was an error
	if err != nil {
		return ""
	}

	// Return the contents of the file
	return ParseSecretFile(contents)
}

// Get the users from the config or file
func GetUsers(conf string, file string) (types.Users, error) {
	// Create a string to store the users
	var users string

	// If neither the config or file is set, return an empty users struct
	if conf == "" && file == "" {
		return types.Users{}, nil
	}

	// If the config (environment) is set, append the users to the users string
	if conf != "" {
		log.Debug().Msg("Using users from config")
		users += conf
	}

	// If the file is set, read the file and append the users to the users string
	if file != "" {
		// Read the file
		contents, err := ReadFile(file)

		// If there isn't an error we can append the users to the users string
		if err == nil {
			log.Debug().Msg("Using users from file")

			// Append the users to the users string
			if users != "" {
				users += ","
			}

			// Parse the file contents into a comma separated list of users
			users += ParseFileToLine(contents)
		}
	}

	// Return the parsed users
	return ParseUsers(users)
}

// Parse the docker labels to the tinyauth labels struct
func GetTinyauthLabels(labels map[string]string) types.TinyauthLabels {
	// Create a new tinyauth labels struct
	var tinyauthLabels types.TinyauthLabels

	// Loop through the labels
	for label, value := range labels {

		// Check if the label is in the tinyauth labels
		if slices.Contains(constants.TinyauthLabels, label) {

			log.Debug().Str("label", label).Msg("Found label")

			// Add the label value to the tinyauth labels struct
			switch label {
			case "tinyauth.oauth.whitelist":
				tinyauthLabels.OAuthWhitelist = strings.Split(value, ",")
			case "tinyauth.users":
				tinyauthLabels.Users = strings.Split(value, ",")
			case "tinyauth.allowed":
				tinyauthLabels.Allowed = value
			case "tinyauth.headers":
				tinyauthLabels.Headers = make(map[string]string)
				headers := strings.Split(value, ",")
				for _, header := range headers {
					headerSplit := strings.Split(header, "=")
					if len(headerSplit) != 2 {
						continue
					}
					tinyauthLabels.Headers[headerSplit[0]] = headerSplit[1]
				}
			}
		}
	}

	// Return the tinyauth labels
	return tinyauthLabels
}

// Check if any of the OAuth providers are configured based on the client id and secret
func OAuthConfigured(config types.Config) bool {
	return (config.GithubClientId != "" && config.GithubClientSecret != "") || (config.GoogleClientId != "" && config.GoogleClientSecret != "") || (config.GenericClientId != "" && config.GenericClientSecret != "")
}

// Filter helper function
func Filter[T any](slice []T, test func(T) bool) (res []T) {
	for _, value := range slice {
		if test(value) {
			res = append(res, value)
		}
	}
	return res
}

// Parse user
func ParseUser(user string) (types.User, error) {
	// Check if the user is escaped
	if strings.Contains(user, "$$") {
		user = strings.ReplaceAll(user, "$$", "$")
	}

	// Split the user by colon
	userSplit := strings.Split(user, ":")

	// Check if the user is in the correct format
	if len(userSplit) < 2 || len(userSplit) > 3 {
		return types.User{}, errors.New("invalid user format")
	}

	// Check for empty strings
	for _, userPart := range userSplit {
		if strings.TrimSpace(userPart) == "" {
			return types.User{}, errors.New("invalid user format")
		}
	}

	// Check if the user has a totp secret
	if len(userSplit) == 2 {
		return types.User{
			Username: userSplit[0],
			Password: userSplit[1],
		}, nil
	}

	// Return the user struct
	return types.User{
		Username:   userSplit[0],
		Password:   userSplit[1],
		TotpSecret: userSplit[2],
	}, nil
}

// Parse secret file
func ParseSecretFile(contents string) string {
	// Split to lines
	lines := strings.Split(contents, "\n")

	// Loop through the lines
	for _, line := range lines {
		// Check if the line is empty
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Return the line
		return strings.TrimSpace(line)
	}

	// Return an empty string
	return ""
}
