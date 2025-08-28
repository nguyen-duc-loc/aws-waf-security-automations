package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/athena"
	"github.com/aws/aws-sdk-go-v2/service/athena/types"
)

// Event is the input event structure for the Lambda function.
type Event struct {
	GlueAccessLogsDatabase string `json:"glueAccessLogsDatabase"`
	AccessLogBucket        string `json:"accessLogBucket"`
	WafLogBucket           string `json:"wafLogBucket"`
	GlueAppAccessLogsTable string `json:"glueAppAccessLogsTable"`
	GlueWafAccessLogsTable string `json:"glueWafAccessLogsTable"`
	AthenaWorkGroup        string `json:"athenaWorkGroup"`
}

// HandleRequest is the main Lambda handler function.
func HandleRequest(ctx context.Context, event Event) error {
	log.Println("[add-athena-partition lambda_handler] Start")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Printf("failed to load configuration, %v", err)
		return err
	}

	athenaClient := athena.NewFromConfig(cfg)

	// Add athena partition for cloudfront or alb logs
	if event.AccessLogBucket != "" && event.GlueAppAccessLogsTable != "" {
		err := executeAthenaQuery(ctx, athenaClient, event.AccessLogBucket, event.GlueAccessLogsDatabase, event.GlueAppAccessLogsTable, event.AthenaWorkGroup)
		if err != nil {
			log.Printf("App access log Athena query execution failed: %s", err)
			// Continue processing even if one fails
		}
	}

	// Add athena partition for waf logs
	if event.WafLogBucket != "" && event.GlueWafAccessLogsTable != "" {
		err := executeAthenaQuery(ctx, athenaClient, event.WafLogBucket, event.GlueAccessLogsDatabase, event.GlueWafAccessLogsTable, event.AthenaWorkGroup)
		if err != nil {
			log.Printf("WAF access log Athena query execution failed: %s", err)
		}
	}

	log.Println("[add-athena-partition lambda_handler] End")
	return nil
}

func buildAthenaQuery(databaseName, tableName string) string {
	now := time.Now().UTC()
	year, month, day, hour := now.Year(), int(now.Month()), now.Day(), now.Hour()

	queryString := fmt.Sprintf("ALTER TABLE \"%s\".\"%s\" ADD PARTITION (year = %d, month = %02d, day = %02d, hour = %02d);",
		databaseName, tableName, year, month, day, hour)

	log.Printf("[build_athena_query] Query string:\n%s\n", queryString)
	return queryString
}

func executeAthenaQuery(ctx context.Context, client *athena.Client, logBucket, databaseName, tableName, workGroup string) error {
	s3Output := fmt.Sprintf("s3://%s/athena_results/", logBucket)
	queryString := buildAthenaQuery(databaseName, tableName)

	log.Printf("[execute_athena_query] Query string:\n%s\nAthena S3 Output Bucket: %s\n", queryString, s3Output)

	input := &athena.StartQueryExecutionInput{
		QueryString: &queryString,
		QueryExecutionContext: &types.QueryExecutionContext{
			Database: &databaseName,
		},
		ResultConfiguration: &types.ResultConfiguration{
			OutputLocation: &s3Output,
			EncryptionConfiguration: &types.EncryptionConfiguration{
				EncryptionOption: types.EncryptionOptionSseS3,
			},
		},
		WorkGroup: &workGroup,
	}

	resp, err := client.StartQueryExecution(ctx, input)
	if err != nil {
		return err
	}

	log.Printf("[execute_athena_query] Query execution response:\n%v", resp)
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}
