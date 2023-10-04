# Logstash 

This is a plugin for [Logstash](https://github.com/elastic/logstash). It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way. All logstash plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/). Need generic logstash help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

For problems or feature requests with this specific plugin, raise a github issue [GITHUB/janmg/logstash-input-azure_blob_storage/](https://github.com/janmg/logstash-input-azure_blob_storage). Pull requests will also be welcomed after discussion through an issue.

## Purpose
This plugin can read from Azure Storage Blobs, for instance JSON diagnostics logs for NSG flow logs or LINE based accesslogs from App Services. 
[Azure Blob Storage](https://azure.microsoft.com/en-us/services/storage/blobs/)

## Alternatives
This plugin was inspired by the Azure diagnostics tools, but should work better for bigger amounts of files. the configuration is not compatible, the configuration azureblob refers to the diagnostics tools plugin and this plugin uses azure_blob_storage
https://github.com/Azure/azure-diagnostics-tools/tree/master/Logstash/logstash-input-azureblob

There is a Filebeat plugin, that may work in the future
https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-input-azure-blob-storage.html

## Innerworking
The plugin depends on the [Ruby library azure-storage-blob](https://rubygems.org/gems/azure-storage-blob/versions/1.1.0) from Microsoft, that depends on Faraday for the HTTPS connection to Azure.

The plugin executes the following steps
1. Lists all the files in the azure storage account. where the path of the files are matching pathprefix
2. Filters on path_filters to only include files that match the directory and file glob (e.g. **/*.json)
3. Save the listed files in a registry of known files and filesizes. (data/registry.dat on azure, or in a file on the logstash instance)
4. List all the files again and compare the registry with the new filelist and put the delta in a worklist
5. Process the worklist and put all events in the logstash queue.
6. if there is time left, sleep to complete the interval. If processing takes more than an inteval, save the registry and continue processing.
7. If logstash is stopped, a stop signal will try to finish the current file, save the registry and than quit

## Installation 
This plugin can be installed through logstash-plugin as documented https://www.elastic.co/guide/en/logstash/current/working-with-plugins.html#listing-plugins. This should pull the latest version from rubygems https://rubygems.org/gems/logstash-input-azure_blob_storage

```
/usr/share/logstash/bin/logstash-plugin install logstash-input-azure_blob_storage
```

For Ubuntu I use these commands, to list, update, remove and install
```
sudo -u logstash /usr/share/logstash/bin/logstash-plugin list --verbose
sudo -u logstash /usr/share/logstash/bin/logstash-plugin update
sudo -u logstash /usr/share/logstash/bin/logstash-plugin update logstash-input-azure_blob_storage
sudo -u logstash /usr/share/logstash/bin/logstash-plugin remove logstash-input-azurestorage
sudo -u logstash /usr/share/logstash/bin/logstash-plugin install logstash-input-azure_blob_storage
```

Alternatively you can use the commands from the build.sh script to build and install the gem locally. This you don't have to do, unless you want to modify the code in lib/logstash/inputs/azure_blob_storage.rb
```
sudo -u logstash gem build logstash-input-azure_blob_storage.gemspec
sudo -u logstash gem install logstash-input-azure_blob_storage-${VERSION}.gem
sudo -u logstash /usr/share/logstash/bin/logstash-plugin install ${GEMPWD}/logstash-input-azure_blob_storage-${VERSION}.gem
```

## Minimal Configuration
The minimum configuration required as input is storageaccount, access_key and container.

/etc/logstash/conf.d/test.conf
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
The registry keeps track of files in the storage account, their size and how many bytes have been processed. Files can grow and the added part will be processed as a partial file. The registry is saved todisk every interval.

The interval is also defines when a new round of listing files and processing data should happen. The NSGFLOWLOG's are written every minute into a new block of the hourly blob. This data can be partially read, because the plugin knows the JSON head and tail and removes the leading comma and fixes the JSON before parsing new events

The registry_create_policy determines at the start of the pipeline if processing should resume from the last known unprocessed file, or to start_fresh ignoring old files and start only processing new events that came after the start of the pipeline. Or start_over to process all the files ignoring the registry.

interval defines the minimum time the registry should be saved to the registry file. By default to 'data/registry.dat' in the storageaccount, but can be also kept on the server running logstash by setting registry_local_path. The registry is kept also in memory, the registry file is only needed in case the pipeline dies unexpectedly. During a normal shutdown the registry is also saved.

When registry_local_path is set to a directory, the registry is saved on the logstash server in that directory. The filename is the pipe.id

with registry_create_policy set to resume and the registry_local_path set to a directory where the registry isn't yet created, should load the registry from the storage account and save the registry on the local server. This allows for a migration to localstorage

For pipelines that use the JSON codec or the JSON_LINE codec, the plugin uses one file to learn how the JSON header and tail look like, they can also be configured manually. Using skip_learning the learning can be disabled.

## Running the pipeline
The pipeline can be started in several ways.
 - On the commandline
   ```
   /usr/share/logstash/bin/logtash -f /etc/logstash/conf.d/test.conf
   ```
 - In the pipeline.yml
   ```
   /etc/logstash/pipeline.yml
   pipe.id = test
   pipe.path = /etc/logstash/conf.d/test.conf
   ```
   and then started as a service
   ```
   service logstash start
   ```
 - As managed pipeline from Kibana

To update a config file on a running instance on the commandline you can add the argument --config.reload.automatic and if you modify the files that are in the pipeline.yml you can send a SIGHUP channel to reload the pipelines where the config was changed. 
[https://www.elastic.co/guide/en/logstash/current/reloading-config.html](https://www.elastic.co/guide/en/logstash/current/reloading-config.html)

## Internal Working 
When the plugin is started, it will read all the filenames and sizes in the blob store excluding the directies of files that are excluded by the "path_filters". After every interval it will write a registry to the storageaccount to save the information of how many bytes per blob (file) are read and processed. After all files are processed and at least one interval has passed a new file list is generated and a worklist is constructed that will be processed. When a file has already been processed before, partial files are read from the offset to the filesize at the time of the file listing. If the codec is JSON partial files will be have the header and tail will be added. They can be configured. If logtype is nsgflowlog, the plugin will process the splitting into individual tuple events. The logtype wadiis may in the future be used to process the grok formats to split into log lines. Any other format is fed into the queue as one event per file or partial file. It's then up to the filter to split and mutate the file format.

By default the root of the json message is named "message", you can modify the content in the filter block

Additional fields can be enabled with addfilename and addall, ecs_compatibility is not yet supported.

The configurations and the rest of the code are in [https://github.com/janmg/logstash-input-azure_blob_storage/tree/master/lib/logstash/inputs](lib/logstash/inputs) [https://github.com/janmg/logstash-input-azure_blob_storage/blob/master/lib/logstash/inputs/azure_blob_storage.rb#L10](azure_blob_storage.rb)

## Codecs
The default codec is json, the plugin should also work with json_lines, line. Other codecs like gzip and csv may work, but this plugin doesn't have specific code to handle them. This plugin reads all the binary from the file and gives it to the codec to make into events. For the logtype nsgflowlogs the plugin will read all the blocks and chops it into one event per rule.
https://www.elastic.co/guide/en/logstash/current/codec-plugins.html

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

Because logstash debug makes logstash very chatty, the option debug_until will for a number of processed events and stops debuging. One file can easily contain thousands of events. The debug_until is useful to monitor the start of the plugin and the processing of the first files.

debug_timer will show detailed information on how much time listing of files took and how long the plugin will sleep to fill the interval and the listing and processing starts again.

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
  stdout { codec => rubydebug }
}

output {
    elasticsearch {
        hosts => "elasticsearch"
        index => "nsg-flow-logs-%{+xxxx.ww}"
    }
}

output {
    file {
        path => /tmp/abuse.txt
        codec => line { format => "%{decision} %{flowstate} %{src_ip} ${dst_port}"}
    }
}

```
A more elaborate input configuration example
```
input {
    azure_blob_storage {
        codec => "json"
        # storageaccount => "yourstorageaccountname"
        # access_key => "Ba5e64c0d3=="
        connection_string => "DefaultEndpointsProtocol=https;AccountName=yourstorageaccountname;AccountKey=Ba5e64c0d3==;EndpointSuffix=core.windows.net"
        container => "insights-logs-networksecuritygroupflowevent"
        logtype => "nsgflowlog"
        prefix => "resourceId=/"
        path_filters => ['**/*.json']
        addfilename => true
        addall => true
        environment => "dev-env"
        registry_create_policy => "resume"
        registry_local_path => "/usr/share/logstash/plugin"
        interval => 300
        debug_timer => true
        debug_until => 1000
        addall => true
        registry_create_policy => "start_over"
    }
}

output {
    elasticsearch {
        hosts => "elasticsearch"
        index => "nsg-flow-logs-%{+xxxx.ww}"
    }
}
```

Another for json_lines on append_blobs
```
input {
    azure_blob_storage {
        codec => json_lines {
          delimiter => "\n"
          charset => "UTF-8"
        }
        # below options are optional
        logtype => "raw"
        append => true
        cleanjson => true
```
The configuration documentation is in the first 100 lines of the code
[GITHUB/janmg/logstash-input-azure_blob_storage/blob/master/lib/logstash/inputs/azure_blob_storage.rb](https://github.com/janmg/logstash-input-azure_blob_storage/blob/master/lib/logstash/inputs/azure_blob_storage.rb)

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

output {
  stdout { codec => rubydebug }
}
```

