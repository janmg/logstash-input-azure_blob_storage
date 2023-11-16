package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"encoding/json"

	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	// "github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
)

type NSGFlowLogs struct {
	Records []struct {
		Time          time.Time `json:"time"`
		SystemID      string    `json:"systemId"`
		Category      string    `json:"category"`
		ResourceID    string    `json:"resourceId"`
		OperationName string    `json:"operationName"`
		Properties    struct {
			Version int `json:"Version"`
			Flows   []struct {
				Rule  string `json:"rule"`
				Flows []struct {
					Mac        string   `json:"mac"`
					FlowTuples []string `json:"flowTuples"`
				} `json:"flows"`
			} `json:"flows"`
		} `json:"properties"`
	} `json:"records"`
}

// Azure Storage Quickstart Sample - Demonstrate how to upload, list, download, and delete blobs.
//
// Documentation References:
// - What is a Storage Account - https://docs.microsoft.com/azure/storage/common/storage-create-storage-account
// - Blob Service Concepts - https://docs.microsoft.com/rest/api/storageservices/Blob-Service-Concepts
// - Blob Service Go SDK API - https://godoc.org/github.com/Azure/azure-storage-blob-go
// - Blob Service REST API - https://docs.microsoft.com/rest/api/storageservices/Blob-Service-REST-API
// - Scalability and performance targets - https://docs.microsoft.com/azure/storage/common/storage-scalability-targets
// - Azure Storage Performance and Scalability checklist https://docs.microsoft.com/azure/storage/common/storage-performance-checklist
// - Storage Emulator - https://docs.microsoft.com/azure/storage/common/storage-use-emulator

func handleError(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

func main() {
	fmt.Printf("NSGFLOWLOG\n")

	ctx := context.Background()
	accountName := ""
	accountKey := ""
	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	handleError(err)
	client, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("https://%s.blob.core.windows.net/", accountName), cred, nil)
	handleError(err)

	// Create the container
	containerName := "insights-logs-networksecuritygroupflowevent"
	fmt.Printf("Creating a container named %s\n", containerName)
	// _, err = client.CreateContainer(ctx, containerName, nil)
	// handleError(err)

	// Upload to data to blob storage
	//fmt.Printf("Uploading a blob named %s\n", blobName)
	//_, err = client.UploadBuffer(ctx, containerName, blobName, data, &azblob.UploadBufferOptions{})
	//handleError(err)

	// List the blobs in the container
	fmt.Println("Listing the blobs in the container:")

	pager := client.NewListBlobsFlatPager(containerName, &azblob.ListBlobsFlatOptions{
		Include: azblob.ListBlobsInclude{Snapshots: true, Versions: true},
	})

	for pager.More() {
		resp, err := pager.NextPage(context.TODO())
		handleError(err)

		for _, blob := range resp.Segment.BlobItems {
			fmt.Println(*blob.Name)
		}
	}

	// ListBlockBlob
	blobName := "resourceId=/SUBSCRIPTIONS/F5DD6E2D-1F42-4F54-B3BD-DBF595138C59/RESOURCEGROUPS/VM/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/OCTOBER-NSG/y=2023/m=10/d=31/h=13/m=00/macAddress=002248A31CA3/PT1H.json"
	blobURL := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", accountName, containerName, blobName)

	blockBlobClient, err := blockblob.NewClientWithSharedKeyCredential(blobURL, cred, nil)
	handleError(err)

	blockList, err := blockBlobClient.GetBlockList(context.Background(), blockblob.BlockListTypeAll, nil)
        fmt.Println(blockList.BlockList.CommittedBlocks)

	fmt.Printf("Press enter key to list blob.\n")
        bufio.NewReader(os.Stdin).ReadBytes('\n')
        fmt.Printf("Cleaning up.\n")

	// Download the blob
	get, err := client.DownloadStream(ctx, containerName, blobName, nil)
	handleError(err)

	downloadedData := bytes.Buffer{}
	retryReader := get.NewRetryReader(ctx, &azblob.RetryReaderOptions{})
	_, err = downloadedData.ReadFrom(retryReader)
	handleError(err)

	err = retryReader.Close()
	handleError(err)

	nsgflowlog(downloadedData.Bytes(), blobName)

	// This is where a KAFKA client should be added

	// Needs tracking of which files were read, for flowlogs should use the date/time in the directory structure, only need to remember last processed file

	// Needs implementation of partial reads, incase files grow
	fmt.Printf("Press enter key to exit the application.\n")
	bufio.NewReader(os.Stdin).ReadBytes('\n')
	fmt.Printf("Cleaning up.\n")
}

func nsgflowlog(flowlogs []byte, blobname string) {
	count:=0
	var nsgflowlogs NSGFlowLogs
	json.Unmarshal(flowlogs, &nsgflowlogs)
	// This is where a loop through the nsgflowlogs should happen
	fmt.Println(nsgflowlogs)
	fmt.Println(count)
}

/*
func nsgflowlog(json, blobname)
{
    count=0

    // TODO: create structs for with parsing
    nsg, _ := json.Marshal(true)
    fmt.Println(string(bolB))

    begin
       json["records"].each do |record|
                resource = resource(record["resourceId"])
                # resource = { :subscription => res[:subscription], :resourcegroup => res[:resourcegroup], :nsg => res[:nsg] }
                extras = { :time => record["time"], :system => record["systemId"], :mac => record["macAddress"], :category => record["category"], :operation => record["operationName"] }
                @logger.trace(resource.to_s)
                record["properties"]["flows"].each do |flows|
                    rule = resource.merge ({ :rule => flows["rule"]})
                    flows["flows"].each do |flowx|
                        flowx["flowTuples"].each do |tup|
                            tups = tup.split(',')
                            ev = rule.merge({:unixtimestamp => tups[0], :src_ip => tups[1], :dst_ip => tups[2], :src_port => tups[3], :dst_port => tups[4], :protocol => tups[5], :direction => tups[6], :decision => tups[7]})
                            if (record["properties"]["Version"]==2)
                                tups[9] = 0 if tups[9].nil?
                                tups[10] = 0 if tups[10].nil?
                                tups[11] = 0 if tups[11].nil?
                                tups[12] = 0 if tups[12].nil?
                                ev.merge!( {:flowstate => tups[8], :src_pack => tups[9], :src_bytes => tups[10], :dst_pack => tups[11], :dst_bytes => tups[12]} )
                            end
                            @logger.trace(ev.to_s)
                            if @addfilename
                                ev.merge!( {:filename => name } )
                            end
                            unless @environment.nil?
                                ev.merge!( {:environment => environment } )
                            end
                            if @addall
                                ev.merge!( extras )
                            end

}
*/
