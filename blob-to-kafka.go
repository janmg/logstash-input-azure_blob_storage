package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blockblob"
	"github.com/confluentinc/confluent-kafka-go/v2/kafka"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
	// https://github.com/Shopify/sarama
	// https://pkg.go.dev/github.com/twmb/kafka-go/pkg/kgo
	// https://github.com/streadway/amqp
	// https://github.com/rabbitmq/amqp091-go
)

/*
config viper config reload on fsnotify
blob listing
path filtering
keeping registry?
reading full blobs
reading partial blobs blocks, tracking start and end
detecting json, nsgflowlogs
tracking of time and read sequential file list
printing out to stdout or logfile
format events
send to stream
*/

// structs for extracting nsgflowlogs
type flows struct {
	Mac        string   `json:"mac"`
	FlowTuples []string `json:"flowTuples"`
}
type properties struct {
	Version int `json:"Version"`
	Flows   []struct {
		Rule  string  `json:"rule"`
		Flows []flows `json:"flows"`
	} `json:"flows"`
}
type NSGFlowLogs struct {
	Records []struct {
		Time          time.Time  `json:"time"`
		SystemID      string     `json:"systemId"`
		MacAddress    string     `json:"macAddress"`
		Category      string     `json:"category"`
		ResourceID    string     `json:"resourceId"`
		OperationName string     `json:"operationName"`
		Properties    properties `json:"properties"`
	} `json:"records"`
}

// struct for (temporary) storing event in flat format as json compatbile struct, to easily transform the event to csv or ecs
type flatevent struct {
	Time          time.Time `json:"time"`
	SystemID      string    `json:"systemId"`
	MACAdress     string    `json:"macAddress"`
	Category      string    `json:"category"`
	ResourceID    string    `json:"resourceId"`
	OperationName string    `json:"operationName"`
	Version       int       `json:"Version"`
	Rule          string    `json:"rule"`
	Mac           string    `json:"mac"`
	Unixtime      string    `json:"unixtime"`
	SrcIP         string    `json:"srcip"`
	DstIP         string    `json:"dstip"`
	SrcPort       string    `json:"srcport"`
	DstPort       string    `json:"dstport"`
	Proto         string    `json:"proto"`
	Direction     string    `json:"direction"`
	Action        string    `json:"action"`
	State         string    `json:"state"`
	SrcPackets    int       `json:"srcpackets"`
	SrcBytes      int       `json:"srcbytes"`
	DstPackets    int       `json:"dstpackets"`
	DstBytes      int       `json:"dstbytes"`
}

// struct to store an array of flatevents, before batching to output
type events struct {
	events []flatevent
}

// struct for outputting in Logstash ECS format
type ecsevent struct {
	/*      Ecs struct {
	                Version string `json:"version"`
	        } string `json:"ecs"`
	        ...

	        // https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
	        ecs.set("ecs.version", "1.0.0")
	        ecs.set("@timestamp", old.timestamp)
	        ecs.set("cloud.provider", "azure")
	        ecs.set("cloud.account.id", old.get("[subscription]")
	        ecs.set("cloud.project.id", old.get("[environment]")
	        ecs.set("file.name", old.get("[filename]")
	        ecs.set("event.category", "network")
	        if old.get("[decision]") == "D"
	            ecs.set("event.type", "denied")
	        else
	            ecs.set("event.type", "allowed")
	        end
	        ecs.set("event.action", "")
	        ecs.set("rule.ruleset", old.get("[nsg]")
	        ecs.set("rule.name", old.get("[rule]")
	        ecs.set("trace.id", old.get("[protocol]")+"/"+old.get("[src_ip]")+":"+old.get("[src_port]")+"-"+old.get("[dst_ip]")+":"+old.get("[dst_port]")
	        # requires logic to match sockets and flip src/dst for outgoing.
	        ecs.set("host.mac", old.get("[mac]")
	        ecs.set("source.ip", old.get("[src_ip]")
	        ecs.set("source.port", old.get("[src_port]")
	        ecs.set("source.bytes", old.get("[srcbytes]")
	        ecs.set("source.packets", old.get("[src_pack]")
	        ecs.set("destination.ip", old.get("[dst_ip]")
	        ecs.set("destination.port", old.get("[dst_port]")
	        ecs.set("destination.bytes", old.get("[dst_bytes]")
	        ecs.set("destination.packets", old.get("[dst_packets]")
	        if old.get("[protocol]") = "U"
	            ecs.set("network.transport", "udp")
	        else
	            ecs.set("network.transport", "tcp")
	        end
	        if old.get("[decision]") == "I"
	            ecs.set("network.direction", "incoming")
	        else
	            ecs.set("network.direction", "outgoing")
	        end
	        ecs.set("network.bytes", old.get("[src_bytes]")+old.get("[dst_bytes]")
	        ecs.set("network.packets", old.get("[src_packets]")+old.get("[dst_packets]")
	        return ecs
	*/
}

type output struct {
	exhaust string
	connect string
	format  string
}

func handleError(err error) {
	if err != nil {
		log.Fatal(err.Error())
	}
}

var lookup []output

func main() {
	fmt.Printf("NSGFLOWLOG\n")

	// https://github.com/spf13/viper#watching-and-re-reading-config-files
	viper.SetConfigFile("blob-to-kafka.conf")
	viper.ReadInConfig()
	fmt.Println(viper.Get("PORT"))

	ctx := context.Background()
	accountName := viper.GetString("accountName")
	accountKey := viper.GetString("accountKey")
	containerName := viper.GetString("containerName")
	cloud := "blob.core.windows.net"

	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Println("Config file changed:", e.Name)
		accountName = viper.GetString("accountName")
		accountKey = viper.GetString("accountKey")
		containerName = viper.GetString("containerName")
		cloud = viper.GetString("cloud")
		lookup = nil
		lookup = append(lookup, output{"stdout", "", "Flat"})
		lookup = append(lookup, output{"summary", "", "Flat"})
		lookup = append(lookup, output{"azurehub", viper.GetString("eventhub.connectionString"), viper.GetString("eventhub.format")})
	})

	cred, err := azblob.NewSharedKeyCredential(accountName, accountKey)
	handleError(err)
	client, err := azblob.NewClientWithSharedKeyCredential(fmt.Sprintf("https://%s.%s/", accountName, cloud), cred, nil)
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
	blobURL := fmt.Sprintf("https://%s.%s/%s/%s", accountName, cloud, containerName, blobName)

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
	count := 0
	box := events{[]flatevent{}}

	var nsgflowlogs NSGFlowLogs
	json.Unmarshal(flowlogs, &nsgflowlogs)
	for _, elements := range nsgflowlogs.Records {
		var event flatevent
		event.Time = elements.Time
		event.Version = elements.Properties.Version
		event.SystemID = elements.SystemID
		event.MACAdress = elements.MacAddress
		event.Category = elements.Category
		event.ResourceID = elements.ResourceID
		event.OperationName = elements.OperationName
		event.Version = elements.Properties.Version
		for _, flows := range elements.Properties.Flows {
			event.Rule = flows.Rule
			for _, flow := range flows.Flows {
				event.Mac = flow.Mac
				for _, tuples := range flow.FlowTuples {
					event = addtuples(event, tuples)
					fmt.Println(tuples)
					box.AddItem(event)
					fmt.Println(box.events)
					count++
				}
			}
		}
	}
	fmt.Println(count)
}

func (box *events) AddItem(item flatevent) []flatevent {
	box.events = append(box.events, item)
	return box.events
}

func addtuples(event flatevent, nsgflow string) flatevent {
	tups := strings.Split(nsgflow, ",")
	event.Unixtime = tups[0]
	event.SrcIP = tups[1]
	event.DstIP = tups[2]
	event.SrcPort = tups[3]
	event.DstPort = tups[4]
	event.Proto = tups[5]
	event.Direction = tups[6]
	event.Action = tups[7]
	if event.Version == 2 {
		event.State = tups[8]
		event.SrcPackets = zeroIfEmpty(tups[9])
		event.SrcBytes = zeroIfEmpty(tups[10])
		event.DstPackets = zeroIfEmpty(tups[11])
		event.DstBytes = zeroIfEmpty(tups[12])
	}
	// nice moment to keep some socket statistics
	// socket(src_ip-src_port+dst_port-dst_port, begintime, src_packets, src_bytes, dst_packets, dst_bytes)
	return event
}

func zeroIfEmpty(s string) int {
	if len(s) == 0 {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err == nil {
		return n
	}
	return 0
}

func send(nsg []events) {
	// loop through lookup, prep desired format
	//csv:=
	//ecs:=
	output := "eventhub"
	switch output {
	case "kafka":
		sendKafka(nsg)
	case "eventhub":
		sendAzure(nsg)
	case "mqtt":
		sendMQTT(nsg)
	case "ampq":
		sendAMPQ(nsg)
	case "file":
		appendFile(nsg)
	case "stdout":
		stdout(nsg)
	}
}

func sendAzure(events []flatevent) {
	fmt.Println("Azure sending")
	// "containerName"

	// "Endpoint=sb://nsgflowlogs.servicebus.windows.net/;SharedAccessKeyName=abc;SharedAccessKey=123"
	// *.servicebus.chinacloudapi.cn, *.servicebus.usgovcloudapi.net, or *.servicebus.cloudapi.de
	connectionString := "xxx"
	kfk, err := azeventhubs.NewProducerClientFromConnectionString(connectionString, "xxx", nil)
	//kfk, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": "nsgflowlogs.servicebus.windows.net"})
	handleError(err)

	defer kfk.Close(context.TODO())

	//event := eventhub.NewEventFromString(nsg)
	//err = kfk.SendEventDataBatch(context.Background(), events)
	//SendBatch(ctx, batch)
	handleError(err)
}

func sendKafka(nsg string) {
	fmt.Println("Kafka sending")
	topic := "insights-logs-networksecuritygroupflowevent"
	// "containerName"

	kfk, err := kafka.NewProducer(&kafka.ConfigMap{"bootstrap.servers": "localhost"})
	handleError(err)

	defer kfk.Close()

	kfk.Produce(&kafka.Message{
		TopicPartition: kafka.TopicPartition{Topic: &topic, Partition: kafka.PartitionAny},
		Value:          []byte(nsg),
	}, nil)
}

func sendAMPQ(nsg string) {
	fmt.Println("AMPQ sending")
}

func sendMQTT(nsg string) {
	fmt.Println("MQTT sending")
}

func appendFile(nsg string) {
	fmt.Println(nsg)
}

func stdout(nsg string) {
	fmt.Println(nsg)
}

func summary(nsg string) {
	fmt.Println(nsg)
}
