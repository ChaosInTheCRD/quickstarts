package main

type ScanPayload struct {
	Target       string `json:"target"`
	OutputFormat string `json:"output_format"`
}

type ScanResult struct {
	Succeeded bool    `json:"succeeded"`
	Result    *[]byte `json:"result"`
}

type InventoryItem struct {
	ItemName    string `json:"item_name"`
	PerItemCost int    `json:"per_item_cost"`
	Quantity    int    `json:"quanity"`
}

type ScanRequest struct {
	RequestID    string `json:"request_id"`
	Target       string `json:"target"`
	OutputFormat string `json:"output_format"`
}
type InventoryRequest struct {
	RequestID string `json:"request_id"`
	ItemName  string `json:"item_name"`
	Quantity  int    `json:"quanity"`
}

type InventoryResult struct {
	Success       bool          `json:"success"`
	InventoryItem InventoryItem `json:"inventory_item"`
}

type PaymentRequest struct {
	RequestID          string `json:"request_id"`
	ItemBeingPurchased string `json:"item_being_purchased"`
	Amount             int    `json:"amount"`
	Quantity           int    `json:"quantity"`
}

type ApprovalRequired struct {
	Approval bool `json:"approval"`
}

type Notification struct {
	Message string `json:"message"`
}
