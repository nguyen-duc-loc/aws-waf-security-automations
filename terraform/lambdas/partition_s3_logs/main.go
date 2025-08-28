package main

import (
	"context"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var s3Client *s3.Client

func parseCloudFrontLogs(key, filename string) (string, error) {
	re := regexp.MustCompile(`(\d{4})-(\d{2})-(\d{2})-(\d{2})`)
	matches := re.FindStringSubmatch(key)
	if len(matches) < 5 {
		return "", fmt.Errorf("could not parse timestamp from key: %s", key)
	}
	year, month, day, hour := matches[1], matches[2], matches[3], matches[4]
	dest := fmt.Sprintf("AWSLogs-Partitioned/year=%s/month=%s/day=%s/hour=%s/%s", year, month, day, hour, filename)
	return dest, nil
}

func parseALBLogs(key, filename string) (string, error) {
	yearRegex := regexp.MustCompile(`(\d{4})/(\d{2})/(\d{2})`)
	hourRegex := regexp.MustCompile(`(\d{8})T(\d{2})`)

	yearMatches := yearRegex.FindStringSubmatch(key)
	if len(yearMatches) < 4 {
		return "", fmt.Errorf("could not parse year/month/day from key: %s", key)
	}
	year, month, day := yearMatches[1], yearMatches[2], yearMatches[3]

	hourMatches := hourRegex.FindStringSubmatch(filename)
	if len(hourMatches) < 3 {
		return "", fmt.Errorf("could not parse hour from filename: %s", filename)
	}
	hour := hourMatches[2]

	dest := fmt.Sprintf("AWSLogs-Partitioned/year=%s/month=%s/day=%s/hour=%s/%s", year, month, day, hour, filename)
	return dest, nil
}

// HandleRequest is the main Lambda handler function.
func HandleRequest(ctx context.Context, s3Event events.S3Event) error {
	log.Println("[partition_s3_logs lambda_handler] Start")

	if s3Client == nil {
		cfg, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			log.Printf("failed to load configuration, %v", err)
			return err
		}
		s3Client = s3.NewFromConfig(cfg)
	}

	keepOriginalData := strings.ToUpper(os.Getenv("KEEP_ORIGINAL_DATA"))
	endpoint := strings.ToUpper(os.Getenv("ENDPOINT"))
	log.Printf("\n[partition_s3_logs lambda_handler] KEEP ORIGINAL DATA: %s; End POINT: %s.", keepOriginalData, endpoint)

	count := 0
	for _, record := range s3Event.Records {
		bucket := record.S3.Bucket.Name
		key, err := url.QueryUnescape(record.S3.Object.Key)
		if err != nil {
			log.Printf("failed to unescape key: %s, error: %v", record.S3.Object.Key, err)
			continue
		}

		keyParts := strings.Split(key, "/")
		filename := keyParts[len(keyParts)-1]

		var dest string
		if endpoint == "CLOUDFRONT" {
			dest, err = parseCloudFrontLogs(key, filename)
		} else {
			dest, err = parseALBLogs(key, filename)
		}

		if err != nil {
			log.Println(err)
			continue
		}

		sourcePath := bucket + "/" + key
		destPath := bucket + "/" + dest

		_, err = s3Client.CopyObject(ctx, &s3.CopyObjectInput{
			Bucket:     aws.String(bucket),
			CopySource: aws.String(url.PathEscape(sourcePath)),
			Key:        aws.String(dest),
		})
		if err != nil {
			log.Printf("failed to copy object from %s to %s, %v", sourcePath, destPath, err)
			continue
		}
		log.Printf("\n[partition_s3_logs lambda_handler] Copied file %s to destination %s", sourcePath, destPath)

		if keepOriginalData == "NO" {
			_, err = s3Client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket: aws.String(bucket),
				Key:    aws.String(key),
			})
			if err != nil {
				log.Printf("failed to delete object %s, %v", sourcePath, err)
				continue
			}
			log.Printf("\n[partition_s3_logs lambda_handler] Removed file %s", sourcePath)
		}
		count++
	}

	log.Printf("\n[partition_s3_logs lambda_handler] Successfully partitioned %d file(s).", count)
	log.Println("[partition_s3_logs lambda_handler] End")
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
