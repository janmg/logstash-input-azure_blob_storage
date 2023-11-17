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
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	// https://github.com/Shopify/sarama
	// https://pkg.go.dev/github.com/twmb/kafka-go/pkg/kgo
	// https://github.com/streadway/amqp
	// https://github.com/rabbitmq/amqp091-go
)

type flows struct {
        Mac        string   `json:"mac"`
        FlowTuples []string `json:"flowTuples"`
}

type properties struct {
        Version int `json:"Version"`
        Flows   []struct {
                Rule  string `json:"rule"`
		Flows []flows `json:"flows"`
        } `json:"flows"`
}

type NSGFlowLogs struct {
	Records []struct {
		Time          time.Time `json:"time"`
		SystemID      string    `json:"systemId"`
		Category      string    `json:"category"`
		ResourceID    string    `json:"resourceId"`
		OperationName string    `json:"operationName"`
		Properties    properties `json:"properties"`
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
        accountName := "janmg"
        accountKey := ""
        containerName := "insights-logs-networksecuritygroupflowevent"

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	handleError(err)
	client, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("https://%s.blob.core.windows.net/", accountName), cred, nil)
	handleError(err)

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
	for _, elements := range nsgflowlogs.Records {
		//version := elements.Properties.Version
		for _, flows := range elements.Properties.Flows {
			fmt.Println(flows)
			for _, flow := range flows.Flows {
				fmt.Println(flow.Mac)
				for _, tuples := range flow.FlowTuples {
					fmt.Println(tuples)
					send(tuples)
					count++
				}
			}
		}
	}
	fmt.Println(count)
}
/*
func tuples(nsgflow string,version int) {
	tups := nsgflow.split(',')
        //ev = rule.merge({:unixtimestamp => tups[0], :src_ip => tups[1], :dst_ip => tups[2], :src_port => tups[3], :dst_port => tups[4], :protocol => tups[5], :direction => tups[6], :decision => tups[7]})
        if (version==2) {
          //     tups[9] = 0 if tups[9].nil?
          //     tups[10] = 0 if tups[10].nil?
          //     tups[11] = 0 if tups[11].nil?
          //     tups[12] = 0 if tups[12].nil?
          //     ev.merge!( {:flowstate => tups[8], :src_pack => tups[9], :src_bytes => tups[10], :dst_pack => tups[11], :dst_bytes => tups[12]} )
	}
}
*/
func send(nsg string) {
	fmt.Println("Kafka sending")
	topic := "insights-logs-networksecuritygroupflowevent"
	// "containerName"

	kfk, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": "localhost"})
        handleError(err)

        defer kfk.Close()

	kfk.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Value: []byte(nsg),
	}, nil)
}
/*
func nsgflowlog(json, blobname)
{
resource = resource(record["resourceId"])
# resource = { :subscription => res[:subscription], :resourcegroup => res[:resourcegroup], :nsg => res[:nsg] }
extras = { :time => record["time"], :system => record["systemId"], :mac => record["macAddress"], :category => record["category"], :operation => record["operationName"] }
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

	if @addfilename
          ev.merge!( {:filename => name } )
        unless @environment.nil?
          ev.merge!( {:environment => environment } )
        if @addall
          ev.merge!( extras )
*/
