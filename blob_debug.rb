# https://github.com/Azure-Samples/storage-blob-ruby-getting-started

require 'azure/storage/blob'
require 'json'
require 'pathname'

storageaccount = "logstashplugingtest"
access_key = ""
container = "insights-logs-networksecuritygroupflowevent"
registry_path = "data/registry.dat"
prefix = "resourceId="

client = Azure::Storage::Blob::BlobService.create(
    storage_account_name: storageaccount,
    storage_access_key: access_key
)

blobs = client.list_blobs(container, { maxresults:10, prefix: @prefix} )
puts
puts "=== list blobs ==="
printf("%-40s %-25s %-30s %12s %-16s %6s\n", "path","file","last_modified","length","type","commit")
blobs.each do |blob|
    blobprop = client.get_blob_properties(container, blob.name)
    pn = Pathname.new(blob.name)
    #puts "#{blobprop.inspect}"
    # https://github.com/Azure/azure-storage-ruby/blob/v1.1.0-blob/blob/lib/azure/storage/blob/serialization.rb#L202
    printf("%-40s %-25s %-30s %12d %-16s %6d\n", pn.dirname.to_s[0..39], pn.basename.to_s[0..24], blobprop.properties[:last_modified], blobprop.properties[:content_length], blobprop.properties[:blob_type], blobprop.properties[:committed_count].to_i)
end

# HelloAppendBlobWorld.txt {:last_modified=>"Tue, 22 Dec 2020 13:46:50 GMT", :etag=>"\"0x8D8A68008FCB91A\"", :lease_status=>"unlocked", :lease_state=>"available", :lease_duration=>nil, :content_length=>55, :content_type=>"application/octet-stream", :content_encoding=>nil, :content_language=>nil, :content_disposition=>nil, :content_md5=>nil, :cache_control=>nil, :blob_type=>"AppendBlob", :copy_id=>nil, :copy_status=>nil, :copy_source=>nil, :copy_progress=>nil, :copy_completion_time=>nil, :copy_status_description=>nil, :accept_ranges=>0, :committed_count=>2}


blobname = "resourceId=/SUBSCRIPTIONS/1EBBA7BE-B058-4313-B9F7-E84105919D60/RESOURCEGROUPS/LOGSTASH-INPUT-AZURE_BLOB_STORAGE/PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/UBUNTU-NSG/y=2020/m=12/d=15/h=20/m=00/macAddress=000D3A2CEE5A/PT1H.json"
#blobname = 'HelloAppendBlobWorld.txt'
blocks = client.list_blob_blocks(container, blobname)
puts
#puts blocks

puts
puts "=== block list for #{blobname} ==="
blocks[:committed].each do |block|
    puts "#{block.name} #{block.size}"
end
puts "=== uncommitted block list for #{blobname} ==="
blocks[:uncommitted].each do |block|
    puts "#{block.size}"
end
puts

def donotrun
    # Runs basic append blob samples for Azure Storage Blob service.
    blob_name = 'HelloAppendBlobWorld.txt'
    puts "Create a container with name #{container}"
    # client.create_container(container)
    puts "Create Append Blob with name #{blob_name}"
    client.create_append_blob(container, blob_name)
    puts 'Write to Append Blob'
    client.append_blob_block(container, blob_name, 'Hello Append Blob world!;')
    client.append_blob_block(container, blob_name, 'Hello Again Append Blob world!')
    puts 'List Blobs in Container'
    blobs = client.list_blobs(container)
    blobs.each do |_blob|
        puts "  Blob Name: #{blob_name}"
    end
    puts 'Read Append blob'
    append_blob = client.get_blob(container, blob_name)
    puts append_blob[0].name + ' contents:'
    puts append_blob[1]
    puts ''
end
