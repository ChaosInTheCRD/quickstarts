package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/dapr/go-sdk/client"
	dapr "github.com/dapr/go-sdk/client"
	"github.com/dapr/go-sdk/workflow"
)

const WF_STATE_STORE_NAME = "wf-statestore"

func chunkBytes(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	dataLen := len(data)

	for i := 0; i < dataLen; i += chunkSize {
		end := i + chunkSize
		if end > dataLen {
			end = dataLen
		}
		chunks = append(chunks, data[i:end])
	}
	return chunks
}

func assembleChunks(chunks [][]byte) []byte {
	return bytes.Join(chunks, nil)
}

// ContainerScanWorkflow is the main workflow for orchestrating activities in the container scan process.
func ContainerScanWorkflow(ctx *workflow.WorkflowContext) (any, error) {
	wfID := ctx.InstanceID()
	var scanPayload ScanPayload
	if err := ctx.GetInput(&scanPayload); err != nil {
		fmt.Println("Error in GetInput: ", err.Error())
		return nil, err
	}

	err := ctx.CallActivity(NotifyActivity, workflow.ActivityInput(Notification{
		Message: fmt.Sprintf("Received workflow id %s to perform a vulnerability scan on %s", wfID, scanPayload.Target),
	})).Await(nil)
	if err != nil {
		return ScanResult{Succeeded: false}, err
	}

	fmt.Println("CHANGE THE PATH BELOW HERE")
	sbom, err := os.ReadFile("/Users/chaosinthecrd/Git/dapr-quickstarts/workflows/go/sdk/judge-actor/sbom.cdx.json")
	if err != nil {
		return nil, err
	}

	client, err := dapr.NewClient()
	if err != nil {
		panic(err)
	}

	const chunkSize = 512 * 1024
	chunks := chunkBytes(sbom, chunkSize)

	sctx := context.Background()
	fmt.Println("Testing saving state")
	for i, chunk := range chunks {
		err = client.SaveState(sctx, WF_STATE_STORE_NAME, fmt.Sprintf("%s-%d", "tester122445", i), chunk, nil)
		if err != nil {
			return nil, err
		}
	}

	fmt.Println("saved the state")

	fmt.Println("Testing getting state")
	fetchedChunks := make([][]byte, len(chunks))
	for i := range chunks {
		res, err := client.GetState(sctx, WF_STATE_STORE_NAME, fmt.Sprintf("%s-%d", "tester122445", i), nil)
		if err != nil {
			return nil, err
		}

		fetchedChunks = append(fetchedChunks, res.Value)
	}

	sbom = assembleChunks(fetchedChunks)

	fmt.Println("got result:", string(sbom))

	tmpFile, err := os.CreateTemp(os.TempDir(), "sbom.json")
	if err != nil {
		return nil, err
	}

	_, err = tmpFile.Write(sbom)
	if err != nil {
		return nil, err
	}

	fmt.Println("File written to: ", tmpFile.Name())

	var scanResult ScanResult
	if err := ctx.CallActivity(ContainerScanActivity, workflow.ActivityInput(ScanRequest{
		RequestID:    wfID,
		Target:       tmpFile.Name(),
		OutputFormat: scanPayload.OutputFormat,
	})).Await(&scanResult); err != nil {
		fmt.Println("Error in ContainerScanActivity")
		fmt.Println(err.Error())
		return ScanResult{Succeeded: false}, err
	}

	fmt.Println("ScanResult: ", string(*scanResult.Result))

	return scanResult, err
}

// NotifyActivity outputs a notification message
func NotifyActivity(ctx workflow.ActivityContext) (any, error) {
	var input Notification
	if err := ctx.GetInput(&input); err != nil {
		return "", err
	}
	fmt.Printf("NotifyActivity: %s\n", input.Message)
	return nil, nil
}

// ProcessPaymentActivity is used to process a payment
func ProcessPaymentActivity(ctx workflow.ActivityContext) (any, error) {
	var input PaymentRequest
	if err := ctx.GetInput(&input); err != nil {
		return "", err
	}
	fmt.Printf("ProcessPaymentActivity: %s for %d - %s (%dUSD)\n", input.RequestID, input.Quantity, input.ItemBeingPurchased, input.Amount)
	return nil, nil
}

// ContainerScanActivity is used to scan a container
func ContainerScanActivity(ctx workflow.ActivityContext) (any, error) {
	fmt.Println("ContainerScanActivity: Starting container scan")
	var input ScanRequest
	if err := ctx.GetInput(&input); err != nil {
		return nil, err
	}
	fmt.Printf("ContainerScanActivity: Scanning %s for %s\n", input.Target, input.OutputFormat)
	output, err := runGrype(input.Target)
	if err != nil {
		return ScanResult{Succeeded: false, Result: &output}, err
	}

	fmt.Println("JSON: ", string(output))
	return ScanResult{Succeeded: true, Result: &output}, nil
}

// VerifyInventoryActivity is used to verify if an item is available in the inventory
func VerifyInventoryActivity(ctx workflow.ActivityContext) (any, error) {
	var input InventoryRequest
	if err := ctx.GetInput(&input); err != nil {
		return nil, err
	}
	fmt.Printf("VerifyInventoryActivity: Verifying inventory for order %s of %d %s\n", input.RequestID, input.Quantity, input.ItemName)
	fmt.Println("Sleeping for a few seconds to test...")
	time.Sleep(5 * time.Second)
	fmt.Println("Woke up from sleep")
	dClient, err := client.NewClient()
	if err != nil {
		return nil, err
	}
	item, err := dClient.GetState(context.Background(), stateStoreName, input.ItemName, nil)
	if err != nil {
		return nil, err
	}
	if item == nil {
		return InventoryResult{
			Success:       false,
			InventoryItem: InventoryItem{},
		}, nil
	}
	var result InventoryItem
	if err := json.Unmarshal(item.Value, &result); err != nil {
		log.Fatalf("failed to parse inventory result %v", err)
	}
	fmt.Printf("VerifyInventoryActivity: There are %d %s available for purchase\n", result.Quantity, result.ItemName)
	if result.Quantity >= input.Quantity {
		return InventoryResult{Success: true, InventoryItem: result}, nil
	}
	return InventoryResult{Success: false, InventoryItem: InventoryItem{}}, nil
}

// UpdateInventoryActivity modifies the inventory.
func UpdateInventoryActivity(ctx workflow.ActivityContext) (any, error) {
	var input PaymentRequest
	if err := ctx.GetInput(&input); err != nil {
		return nil, err
	}
	fmt.Printf("UpdateInventoryActivity: Checking Inventory for order %s for %d * %s\n", input.RequestID, input.Quantity, input.ItemBeingPurchased)
	dClient, err := client.NewClient()
	if err != nil {
		return nil, err
	}
	item, err := dClient.GetState(context.Background(), stateStoreName, input.ItemBeingPurchased, nil)
	if err != nil {
		return nil, err
	}
	var result InventoryItem
	err = json.Unmarshal(item.Value, &result)
	if err != nil {
		return nil, err
	}
	newQuantity := result.Quantity - input.Quantity
	if newQuantity < 0 {
		return nil, fmt.Errorf("insufficient inventory for: %s", input.ItemBeingPurchased)
	}
	result.Quantity = newQuantity
	newState, err := json.Marshal(result)
	if err != nil {
		log.Fatalf("failed to marshal new state: %v", err)
	}
	dClient.SaveState(context.Background(), stateStoreName, input.ItemBeingPurchased, newState, nil)
	fmt.Printf("UpdateInventoryActivity: There are now %d %s left in stock\n", result.Quantity, result.ItemName)
	return InventoryResult{Success: true, InventoryItem: result}, nil
}

// RequestApprovalActivity requests approval for the order
func RequestApprovalActivity(ctx workflow.ActivityContext) (any, error) {
	return nil, nil
}
