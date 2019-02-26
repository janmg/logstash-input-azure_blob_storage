# Logstash Plugin

This is a plugin for [Logstash](https://github.com/elastic/logstash).

It is fully free and fully open source. The license is Apache 2.0, meaning you are pretty much free to use it however you want in whatever way.

## Documentation

All plugin documentation are placed under one [central location](http://www.elastic.co/guide/en/logstash/current/).

## Need Help?

Need help? Try #logstash on freenode IRC or the https://discuss.elastic.co/c/logstash discussion forum.

## Enabling NSG Flowlogs
1. Enable Network Watcher in your regions
2. Create Storage account per region
   v1 or v2 are both fine
   Any resource group works fine, NetworkWatcherRG would be the best
3. Enable in Network Watcher for every NSG the NSG Flow logs
   the list_blobs has a limit of 5000 files, with one file per hour per nsg make sure the retention time is set so that all files can be seen. for 180 NSG's with 1 day retention is 4320 files, more retention leads to delays in processing. So either use multiple storage accounts with multiple pipelines, or use the same storage account with a prefix to separate.
4. In storage account there will be a/ container / resourceID 
{storageaccount}.blob.core.windows.net/insights-logs-networksecuritygroupflowevent/resourceId=/SUBSCRIPTIONS/{UUID}/RESOURCEGROUPS/{RG}/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/{NSG}/y=2019/m=02/d=12/h=07/m=00/macAddress={MAC}/PT1H.json
5. Get access to the storageaccount
   - connection string (key1 / key2 ... one string with all the connection details
   - access_key (key1 or key2)
   - sas key shared access signature

## Configuration Examples
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

You can include additional options to tweak the operations
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
        interval => 60
        iplookup => "http://10.0.0.5:6081/ripe.php?ip="
        use_redis => true
        iplist => [
            "{'ip':'10.0.0.4','netname':'Application Gateway','subnet':'10.0.0.0\/24','hostname':'appgw'}",
            "{'ip':'36.156.24.96',netname':'China Mobile','subnet':'36.156.0.0\/16','hostname':'bigbadwolf'}"
        ]
    }
}
```
