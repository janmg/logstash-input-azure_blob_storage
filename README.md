# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

All logstash plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum. For real problems or feature requests, raise a github issue [GITHUB/janmg/logstash-input-azure_blob_storage/](https://github.com/janmg/logstash-input-azure_blob_storage). Pull requests will ionly be merged after discussion through an issue.

## Purpose
This plugin can read from Azure Storage Blobs, for instance diagnostics logs for NSG flow logs or accesslogs from App Services. 
[Azure Blob Storage](https://azure.microsoft.com/en-us/services/storage/blobs/)
This 
## Installation 
This plugin can be installed through logstash-plugin
```
logstash-plugin install logstash-input-azure_blob_storage
```

## Minimal Configuration
The minimum configuration required as input is storageaccount, access_key and container.

```
input {
    azure_blob_storage {
        storageaccount => "yourstorageaccountname"
        access_key => "Ba5e64c0d3=="
        container => "insights-logs-networksecuritygroupflowevent"
    }
}
```

## Additional Configuration
The registry_create_policy is used when the pipeline is started to either resume from the last known unprocessed file, or to start_fresh ignoring old files or start_over to process all the files from the beginning.

interval defines the minimum time the registry should be saved to the registry file (by default 'data/registry.dat'), this is only needed in case the pipeline dies unexpectedly. During a normal shutdown the registry is also saved.

During the pipeline start the plugin uses one file to learn how the JSON header and tail look like, they can also be configured manually.

## Running the pipeline
The pipeline can be started in several ways.
 - On the commandline
   ```
   /usr/share/logstash/bin/logtash -f /etc/logstash/pipeline.d/test.yml
   ```
 - In the pipeline.yml
   ```
   /etc/logstash/pipeline.yml
   pipe.id = test
   pipe.path = /etc/logstash/pipeline.d/test.yml
   ```
 - As managed pipeline from Kibana

Logstash itself (so not specific to this plugin) has a feature where multiple instances can run on the same system. The default TCP port is 9600, but if it's already in use it will use 9601 (and up). To update a config file on a running instance on the commandline you can add the argument --config.reload.automatic and if you modify the files that are in the pipeline.yml you can send a SIGHUP channel to reload the pipelines where the config was changed. 
[https://www.elastic.co/guide/en/logstash/current/reloading-config.html](https://www.elastic.co/guide/en/logstash/current/reloading-config.html)

## Internal Working 
When the plugin is started, it will read all the filenames and sizes in the blob store excluding the directies of files that are excluded by the "path_filters". After every interval it will write a registry to the storageaccount to save the information of how many bytes per blob (file) are read and processed. After all files are processed and at least one interval has passed a new file list is generated and a worklist is constructed that will be processed. When a file has already been processed before, partial files are read from the offset to the filesize at the time of the file listing. If the codec is JSON partial files will be have the header and tail will be added. They can be configured. If logtype is nsgflowlog, the plugin will process the splitting into individual tuple events. The logtype wadiis may in the future be used to process the grok formats to split into log lines. Any other format is fed into the queue as one event per file or partial file. It's then up to the filter to split and mutate the file format.

By default the root of the json message is named "message" so you can modify the content in the filter block

The configurations and the rest of the code are in [https://github.com/janmg/logstash-input-azure_blob_storage/tree/master/lib/logstash/inputs](lib/logstash/inputs) [https://github.com/janmg/logstash-input-azure_blob_storage/blob/master/lib/logstash/inputs/azure_blob_storage.rb#L10](azure_blob_storage.rb)

## Enabling NSG Flowlogs
1. Enable Network Watcher in your regions
2. Create Storage account per region
   v1 or v2 are both fine
   Any resource group works fine, NetworkWatcherRG would be the best
3. Enable in Network Watcher for every NSG the NSG Flow logs
   the list_blobs has a limit of 5000 files, with one file per hour per nsg make sure the retention time is set so that all files can be seen. for 180 NSG's with 1 day retention is 4320 files, more retention leads to delays in processing. So either use multiple storage accounts with multiple pipelines, or use the same storage account with a prefix to separate.
4. In storage account there will be a/ container / resourceID 
{storageaccount}.blob.core.windows.net/insights-logs-networksecuritygroupflowevent/resourceId=/SUBSCRIPTIONS/{UUID}/RESOURCEGROUPS/{RG}/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/{NSG}/y=2019/m=02/d=12/h=07/m=00/macAddress={MAC}/PT1H.json
5. Get credentials of the storageaccount
   - SAS token (shared access signature) starts with a '?'
   - connection string ... one string with all the connection details
   - Access key (key1 or key2)

## Troubleshooting
The default loglevel can be changed in global logstash.yml. On the info level, the plugin save offsets to the registry every interval and will log statistics of processed events (one ) plugin will print for each pipeline the first 6 characters of the ID, in DEBUG the yml log level debug shows details of number of events per (partial) files that are read. 
```
log.level
```
The log level of the plugin can be put into DEBUG through 

```
curl -XPUT 'localhost:9600/_node/logging?pretty' -H 'Content-Type: application/json' -d'{"logger.logstash.inputs.azureblobstorage" : "DEBUG"}'
```


## Other Configuration Examples
For nsgflowlogs, a simple configuration looks like this
```
input {
    azure_blob_storage {
        storageaccount => "yourstorageaccountname"
        access_key => "Ba5e64c0d3=="
        container => "insights-logs-networksecuritygroupflowevent"
    }
}

filter {
    json {
        source => "message"
    }
    mutate {
        add_field => { "environment" => "test-env" }
        remove_field => [ "message" ]
    }
    date {
        match => ["unixtimestamp", "UNIX"]
    }
}

output {
    elasticsearch {
        hosts => "elasticsearch"
        index => "nsg-flow-logs-%{+xxxx.ww}"
    }
}
```

```
input {
    azure_blob_storage {
        storageaccount => "yourstorageaccountname"
        access_key => "Ba5e64c0d3=="
        container => "insights-logs-networksecuritygroupflowevent"
        codec => "json"
        logtype => "nsgflowlog"
        prefix => "resourceId=/"
        registry_create_policy => "resume"
        interval => 300
    }
}
```

For WAD IIS and App Services the HTTP AccessLogs can be retrieved from a storage account as line based events and parsed through GROK. The date stamp can also be parsed with %{TIMESTAMP_ISO8601:log_timestamp}. For WAD IIS logfiles the container is wad-iis-logfiles. In the future grokking may happen already by the plugin.
```
input {
    azure_blob_storage {
        storageaccount => "yourstorageaccountname"
        access_key => "Ba5e64c0d3=="
        container => "access-logs"
        interval => 300
        codec => line
    }
}

filter {
  if [message] =~ "^#" {
    drop {}
  }

  mutate {
    strip => "message"
  }

  grok {
    match => ['message', '(?<timestamp>%{YEAR}-%{MONTHNUM}-%{MONTHDAY} %{HOUR}:%{MINUTE}:%{SECOND}\d+) %{NOTSPACE:instanceId} %{WORD:httpMethod} %{URIPATH:requestUri} %{NOTSPACE:requestQuery} %{NUMBER:port} %{NOTSPACE:username} %{IPORHOST:clientIP} %{NOTSPACE:userAgent} %{NOTSPACE:cookie} %{NOTSPACE:referer} %{NOTSPACE:host} %{NUMBER:httpStatus} %{NUMBER:subresponse} %{NUMBER:win32response} %{NUMBER:sentBytes:int} %{NUMBER:receivedBytes:int} %{NUMBER:timeTaken:int}']
  }

  date {
    match => [ "timestamp", "YYYY-MM-dd HH:mm:ss" ]
    target => "@timestamp"
  }

  mutate {
    remove_field => ["log_timestamp"]
    remove_field => ["message"]
    remove_field => ["win32response"]
    remove_field => ["subresponse"]
    remove_field => ["username"]
    remove_field => ["clientPort"]
    remove_field => ["port"]
    remove_field => ["timestamp"]
  }
}
```

