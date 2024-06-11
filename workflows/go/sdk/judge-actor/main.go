package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/dapr/go-sdk/client"
	"github.com/dapr/go-sdk/workflow"
)

var (
	stateStoreName    = "statestore"
	workflowComponent = "dapr"
	workflowName      = "ContainerScanWorkflow"
	defaultItemName   = "cars"
)

// Server holds the Dapr and workflow clients.
type Server struct {
	daprClient client.Client
}

// Message defines a simple struct to hold a message.
type Message struct {
	Message string `json:"message"`
}

// runHandler handles requests to the "/json" endpoint.
func (s *Server) runHandler(w http.ResponseWriter, r *http.Request) {
	target, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if string(target) == "" {
		http.Error(w, "Target is required", http.StatusBadRequest)
		return
	}

	wfClient, err := workflow.NewClient(workflow.WithDaprClient(s.daprClient))
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(Message{Message: fmt.Sprintf("error creating dapr client: %v", err)})
		return
	}

	scanPayload := ScanPayload{
		Target: string(target),
	}

	id, err := wfClient.ScheduleNewWorkflow(context.Background(), workflowName, workflow.WithInput(scanPayload))
	if err != nil {
		log.Fatalf("failed to start workflow: %v", err)
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(id)
}

// statusHandler gets the status of the workflow.
func (s *Server) statusHandler(w http.ResponseWriter, r *http.Request) {
	// gonnna assume for now that the body only contains the id
	id, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	wfClient, err := workflow.NewClient(workflow.WithDaprClient(s.daprClient))
	if err != nil {
		http.Error(w, "Unable to create workflow client", http.StatusBadRequest)
		return
	}

	metadata, err := wfClient.FetchWorkflowMetadata(context.Background(), string(id))
	if err != nil {
		http.Error(w, "Unable to fetch workflow metadata", http.StatusBadRequest)
		return
	}

	if (metadata.RuntimeStatus == workflow.StatusCompleted) || (metadata.RuntimeStatus == workflow.StatusFailed) || (metadata.RuntimeStatus == workflow.StatusTerminated) {
		fmt.Println("Workflow completed")
	} else if metadata.RuntimeStatus == workflow.StatusRunning {
		fmt.Println("Workflow running")
	}

	fmt.Println("fippyfoo")

	metaJson, err := json.Marshal(metadata)
	if err != nil {
		http.Error(w, "Unable to marshal metadata", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, string(metaJson))
}

// statusHandler gets the status of the workflow.
func (s *Server) killHandler(w http.ResponseWriter, r *http.Request) {
	// gonnna assume for now that the body only contains the id
	id, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	wfClient, err := workflow.NewClient(workflow.WithDaprClient(s.daprClient))
	if err != nil {
		http.Error(w, "Unable to create workflow client", http.StatusBadRequest)
		return
	}

	err = wfClient.TerminateWorkflow(context.Background(), string(id))
	if err != nil {
		http.Error(w, "Unable to terminate workflow", http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Workflow terminated")
}

func main() {
	fmt.Println("*** Welcome to the Dapr Workflow console app sample!")
	fmt.Println("*** Using this app, you can place orders that start workflows.")

	w, err := workflow.NewWorker()
	if err != nil {
		log.Fatalf("failed to start worker: %v", err)
	}

	if err := w.RegisterWorkflow(ContainerScanWorkflow); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(NotifyActivity); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(ContainerScanActivity); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(RequestApprovalActivity); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(VerifyInventoryActivity); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(ProcessPaymentActivity); err != nil {
		log.Fatal(err)
	}
	if err := w.RegisterActivity(UpdateInventoryActivity); err != nil {
		log.Fatal(err)
	}

	if err := w.Start(); err != nil {
		log.Fatal(err)
	}

	daprClient, err := client.NewClient()
	if err != nil {
		log.Fatal(err)
	}

	server := &Server{
		daprClient: daprClient,
	}

	http.HandleFunc("/run", server.runHandler)
	http.HandleFunc("/status", server.statusHandler)
	http.HandleFunc("/kill", server.killHandler)

	port := "8080"
	fmt.Printf("Starting server on port %s...\n", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Could not start server: %s\n", err)
	}
}

// promptForApproval is an example case. There is no user input required here due to this being for testing purposes only.
// It would be perfectly valid to add a wait here or display a prompt to continue the process.
func promptForApproval(id string) {
	wfClient, err := workflow.NewClient()
	if err != nil {
		log.Fatalf("failed to initialise wfClient: %v", err)
	}
	if err := wfClient.RaiseEvent(context.Background(), id, "manager_approval"); err != nil {
		log.Fatal(err)
	}
}

func restockInventory(daprClient client.Client, inventory []InventoryItem) error {
	for _, item := range inventory {
		itemSerialized, err := json.Marshal(item)
		if err != nil {
			return err
		}
		fmt.Printf("adding base stock item: %s\n", item.ItemName)
		if err := daprClient.SaveState(context.Background(), stateStoreName, item.ItemName, itemSerialized, nil); err != nil {
			return err
		}
	}
	return nil
}
