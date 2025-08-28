package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	wafv2types "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
)

const wafMaxIPs = 10000

var wafv2Client *wafv2.Client

// ReputationList represents the structure of the JSON object in the env var.

type ReputationList struct {
	URL string `json:"url"`
}

// HandleRequest is the main Lambda handler function.
func HandleRequest(ctx context.Context) error {
	log.Println("Starting reputation list parser")

	if wafv2Client == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}
		wafv2Client = wafv2.NewFromConfig(cfg)
	}

	reputationListsEnv := os.Getenv("REPUTATION_LISTS")
	if reputationListsEnv == "" {
		return fmt.Errorf("REPUTATION_LISTS environment variable is not set")
	}

	var lists []ReputationList
	if err := json.Unmarshal([]byte(reputationListsEnv), &lists); err != nil {
		return fmt.Errorf("failed to unmarshal REPUTATION_LISTS: %w", err)
	}

	var addressesV4, addressesV6 []string

	for _, list := range lists {
		log.Printf("Processing list: %s", list.URL)
		ips, err := fetchAndParseList(list.URL)
		if err != nil {
			log.Printf("Warning: Failed to process list %s: %v", list.URL, err)
			continue
		}

		for _, ip := range ips {
			if strings.Contains(ip, ":") {
				addressesV6 = append(addressesV6, ip)
			} else {
				addressesV4 = append(addressesV4, ip)
			}
		}
	}

	log.Printf("Found %d IPv4 addresses and %d IPv6 addresses.", len(addressesV4), len(addressesV6))

	// Truncate lists if they exceed WAF limits
	if len(addressesV4) > wafMaxIPs {
		log.Printf("Truncating IPv4 list from %d to %d addresses", len(addressesV4), wafMaxIPs)
		addressesV4 = addressesV4[:wafMaxIPs]
	}
	if len(addressesV6) > wafMaxIPs {
		log.Printf("Truncating IPv6 list from %d to %d addresses", len(addressesV6), wafMaxIPs)
		addressesV6 = addressesV6[:wafMaxIPs]
	}

	scope := wafv2types.Scope(os.Getenv("SCOPE"))

	// Update IPv4 Set
	ipSetNameV4 := os.Getenv("IP_SET_NAME_REPUTATIONV4")
	ipSetArnV4 := os.Getenv("IP_SET_ID_REPUTATIONV4")
	if err := updateIPSet(ctx, scope, ipSetNameV4, ipSetArnV4, addressesV4); err != nil {
		log.Printf("Error updating IPv4 IPSet: %v", err)
	}

	// Update IPv6 Set
	ipSetNameV6 := os.Getenv("IP_SET_NAME_REPUTATIONV6")
	ipSetArnV6 := os.Getenv("IP_SET_ID_REPUTATIONV6")
	if err := updateIPSet(ctx, scope, ipSetNameV6, ipSetArnV6, addressesV6); err != nil {
		log.Printf("Error updating IPv6 IPSet: %v", err)
	}

	log.Println("Reputation list parser finished successfully.")
	return nil
}

func fetchAndParseList(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status: %s", resp.Status)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var validIPs []string
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if _, _, err := net.ParseCIDR(trimmedLine); err == nil {
			validIPs = append(validIPs, trimmedLine)
		}
	}
	return validIPs, nil
}

func updateIPSet(ctx context.Context, scope wafv2types.Scope, name, id string, addresses []string) error {
	if name == "" || id == "" {
		log.Printf("Skipping update for IP set - name or id is empty.")
		return nil
	}
	log.Printf("Updating IPSet: %s", name)

	getIPSetOutput, err := wafv2Client.GetIPSet(ctx, &wafv2.GetIPSetInput{
		Name:  aws.String(name),
		Id:    aws.String(id),
		Scope: scope,
	})
	if err != nil {
		return fmt.Errorf("failed to get IPSet %s: %w", name, err)
	}

	_, err = wafv2Client.UpdateIPSet(ctx, &wafv2.UpdateIPSetInput{
		Name:        aws.String(name),
		Id:          aws.String(id),
		Scope:       scope,
		Addresses:   addresses,
		LockToken:   getIPSetOutput.LockToken,
		Description: getIPSetOutput.IPSet.Description,
	})
	if err != nil {
		return fmt.Errorf("failed to update IPSet %s: %w", name, err)
	}

	log.Printf("Successfully updated IPSet: %s with %d addresses", name, len(addresses))
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
