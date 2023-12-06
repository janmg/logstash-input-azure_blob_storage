# encoding: utf-8
require 'logstash/inputs/base'
#require 'logstash/namespace'
require 'stud/interval'
require 'azure/storage/blob'
require 'json'

# This is a logstash input plugin for files in Azure Storage Accounts. There is a storage explorer in the portal and an application with the same name https://storageexplorer.com.

# https://docs.microsoft.com/en-us/azure/storage/blobs/storage-blobs-introduction
# The hierarchy of an Azure block storage is
# Tenant > Subscription > Account > ResourceGroup > StorageAccount > Container > FileBlobs > Blocks
# A storage account can store blobs, file shares, queus and tables. This plugin is using the Azure ruby plugin to fetch blobs and process the data in the blocks and dealt with blobs growing over time and ignoring archive blobs
#
# block-id                          bytes content
# A00000000000000000000000000000000 12    {"records":[
# D672f4bbd95a04209b00dc05d899e3cce 2576  json objects for 1st minute
# D7fe0d4f275a84c32982795b0e5c7d3a1 2312  json objects for 2nd minute
# Z00000000000000000000000000000000 2     ]}
#
# The azure-storage-ruby connects to the storageaccount and the files are read through get_blob. For partial read the options with start and end ar used. 
# https://github.com/Azure/azure-storage-ruby/blob/master/blob/lib/azure/storage/blob/blob.rb#L89
#
# A storage account has by default a globally unique name, {storageaccount}.blob.core.windows.net which is a CNAME to  Azures blob servers blob.*.store.core.windows.net. A storageaccount has an container and those have a directory and blobs (like files). Blobs have one or more blocks. After writing the blocks, they can be committed. Some Azure diagnostics can send events to an EventHub that can be parse through the plugin logstash-input-azure_event_hubs, but for the events that are only stored in an storage account, use this plugin. The original logstash-input-azureblob from azure-diagnostics-tools is great for low volumes, but it suffers from outdated client, slow reads, lease locking issues and json parse errors.

class LogStash::Inputs::AzureBlobStorage < LogStash::Inputs::Base
    config_name "azure_blob_storage"

    # If undefined, Logstash will complain, even if codec is unused. The codec for nsgflowlog is "json", "json_line" works and the for WADIIS and APPSERVICE is "line".
    default :codec, "json"

    # logtype can be nsgflowlog, wadiis, appservice or raw. The default is raw, where files are read and added as one event. If the file grows, the next interval the file is read from the offset, so that the delta is sent as another event. In raw mode, further processing has to be done in the filter block. If the logtype is specified, this plugin will split and mutate and add individual events to the queue.
    config :logtype, :validate => ['nsgflowlog','wadiis','appservice','raw'], :default => 'raw'

    # The storage account is accessed through Azure::Storage::Blob::BlobService, it needs either a sas_token, connection string or a storageaccount/access_key pair.
    # https://github.com/Azure/azure-storage-ruby/blob/master/blob/lib/azure/storage/blob/blob_service.rb#L42
    config :connection_string, :validate => :password, :required => false

    # The storage account name for the azure storage account.
    config :storageaccount, :validate => :string, :required => false

    # The (primary or secondary) Access Key for the the storage account. The key can be found in the portal.azure.com or through the azure api StorageAccounts/ListKeys. For example the PowerShell command Get-AzStorageAccountKey.
    config :access_key, :validate => :password, :required => false

    # SAS is the Shared Access Signature, that provides restricted access rights. If the sas_token is absent, the access_key is used instead.
    config :sas_token, :validate => :password, :required => false

    # The container of the blobs.
    config :container, :validate => :string, :default => 'insights-logs-networksecuritygroupflowevent'

    # DNS Suffix other then blob.core.windows.net, needed for government cloud.
    config :dns_suffix, :validate => :string, :required => false, :default => 'core.windows.net'

    # For development this can be used to emulate an accountstorage when not available from azure
    #config :use_development_storage, :validate => :boolean, :required => false

    # The registry keeps track of the files that where already procesed.
    # The registry file keeps track of the files that have been processed and until which offset in bytes. It's similar in function
    #
    # The default, `data/registry`, it contains a Ruby Marshal Serialized Hash of the filename the offset read sofar and the filelength the list time a filelisting was done.
    config :registry_path, :validate => :string, :required => false, :default => 'data/registry.dat'

    # If registry_local_path is set to a directory on the local server, the registry is save there instead of the remote blob_storage
    config :registry_local_path, :validate => :string, :required => false

    # The default, `resume`, will load the registry offsets and will start processing files from the offsets.
    # When set to `start_over`, all log files are processed from begining.
    # when set to `start_fresh`, it will read log files that are created or appended since this start of the pipeline.
    config :registry_create_policy, :validate => ['resume','start_over','start_fresh'], :required => false, :default => 'resume'

    # The interval is used to save the registry regularly, when new events have have been processed. It is also used to wait before listing the files again and substracting the registry of already processed files to determine the worklist.
    # waiting time in seconds until processing the next batch. NSGFLOWLOGS append a block per minute, so use multiples of 60 seconds, 300 for 5 minutes, 600 for 10 minutes. The registry is also saved after every interval.
    # Partial reading starts from the offset and reads until the end, so the starting tag is prepended
    config :interval, :validate => :number, :default => 60

    # add the filename as a field into the events
    config :addfilename, :validate => :boolean, :default => false, :required => false

    # add environment
    config :environment, :validate => :string, :required => false

    # add all resource details
    config :addall, :validate => :boolean, :default => false, :required => false

    # debug_until will at the creation of the pipeline for a maximum amount of processed messages shows 3 types of log printouts including processed filenames. After a number of events, the plugin will stop logging the events and continue silently. This is a lightweight alternative to switching the loglevel from info to debug or even trace to see what the plugin is doing and how fast at the start of the plugin. A good value would be approximately 3x the amount of events per file. For instance 6000 events.
    config :debug_until, :validate => :number, :default => 0, :required => false

    # debug_timer show in the logs, the time spent on activities
    config :debug_timer, :validate => :boolean, :default => false, :required => false

    # WAD IIS Grok Pattern
    #config :grokpattern, :validate => :string, :required => false, :default => '%{TIMESTAMP_ISO8601:log_timestamp} %{NOTSPACE:instanceId} %{NOTSPACE:instanceId2} %{IPORHOST:ServerIP} %{WORD:httpMethod} %{URIPATH:requestUri} %{NOTSPACE:requestQuery} %{NUMBER:port} %{NOTSPACE:username} %{IPORHOST:clientIP} %{NOTSPACE:httpVersion} %{NOTSPACE:userAgent} %{NOTSPACE:cookie} %{NOTSPACE:referer} %{NOTSPACE:host} %{NUMBER:httpStatus} %{NUMBER:subresponse} %{NUMBER:win32response} %{NUMBER:sentBytes:int} %{NUMBER:receivedBytes:int} %{NUMBER:timeTaken:int}'

    # skip learning if you use json and don't want to learn the head and tail, but use either the defaults or configure them.
    config :skip_learning, :validate => :boolean, :default => false, :required => false

    # The string that starts the JSON. Only needed when the codec is JSON. When partial file are read, the result will not be valid JSON unless the start and end are put back. the file_head and file_tail are learned at startup, by reading the first file in the blob_list and taking the first and last block, this would work for blobs that are appended like nsgflowlogs. The configuration can be set to override the learning. In case learning fails and the option is not set, the default is to use the 'records' as set by nsgflowlogs.
    config :file_head, :validate => :string, :required => false, :default => ''
    # The string that ends the JSON
    config :file_tail, :validate => :string, :required => false, :default => ''

    # inspect the bytes and remove faulty characters
    config :cleanjson, :validate => :boolean, :default => false, :required => false

    config :append, :validate => :boolean, :default => false, :required => false
    # By default it will watch every file in the storage container. The prefix option is a simple filter that only processes files with a path that starts with that value.
    # For NSGFLOWLOGS a path starts with "resourceId=/". This would only be needed to exclude other paths that may be written in the same container. The registry file will be excluded.
    # You may also configure multiple paths. See an example on the <<array,Logstash configuration page>>.
    # Do not include a leading `/`, as Azure path look like this: `path/to/blob/file.txt`
    config :prefix, :validate => :string, :required => false

    # For filtering on filenames, you can use filename patterns, such as `logs/*.log`. If you use a pattern like `logs/**/*.log`, a recursive search of `logs` will be done for all `*.log` files in the logs directory.
    # For https://www.rubydoc.info/stdlib/core/File.fnmatch
    config :path_filters, :validate => :array, :default => ['**/*'], :required => false



public
    def register
        @pipe_id = Thread.current[:name].split("[").last.split("]").first
        @logger.info("=== #{config_name} #{Gem.loaded_specs["logstash-input-"+config_name].version.to_s} / #{@pipe_id} / #{@id[0,6]} / ruby #{ RUBY_VERSION }p#{ RUBY_PATCHLEVEL } ===")
        @logger.info("If this plugin doesn't work, please raise an issue in https://github.com/janmg/logstash-input-azure_blob_storage")
        @busy_writing_registry = Mutex.new
        # TODO: consider multiple readers, so add pipeline @id or use logstash-to-logstash communication?
        # For now it's difficult because the plugin would then have to synchronize the worklist
    end



    def run(queue)
        # counter for all processed events since the start of this pipeline
        @processed = 0
        @regsaved = @processed

        connect
        @registry = Hash.new
        load_registry()
        @registry.each do |name, file|
            @logger.info("offset: #{file[:offset]} length: #{file[:length]}")
        end

        @is_json = false
        @is_json_line = false
        begin
            if @codec.class.name.eql?("LogStash::Codecs::JSON")
                @is_json = true
            elsif @codec.class.name.eql?("LogStash::Codecs::JSONLines")
                @is_json_line = true
            end
        end


        @head = ''
        @tail = ''
        if @is_json
            # if codec=json sniff one files blocks A and Z to learn file_head and file_tail
            if @logtype == 'nsgflowlog'
                @head = '{"records":['
                @tail = ']}'
            end
            if file_head
                @head = file_head
            end
            if file_tail
                @tail = file_tail
            end
            if !skip_learning
                learn_encapsulation
            end
            @logger.info("head will be: '#{@head}' and tail is set to: '#{@tail}'")
        end


        filelist = Hash.new
        worklist = Hash.new
        @last = start = Time.now.to_i

        # This is the main loop, it
        # 1. Lists all the files in the remote storage account that match the path prefix
        # 2. Filters on path_filters to only include files that match the directory and file glob (**/*.json)
        # 3. Save the listed files in a registry of known files and filesizes.
        # 4. List all the files again and compare the registry with the new filelist and put the delta in a worklist
        # 5. Process the worklist and put all events in the logstash queue.
        # 6. if there is time left, sleep to complete the interval. If processing takes more than an inteval, save the registry and continue.
        # 7. If stop signal comes, finish the current file, save the registry and quit
        while !stop?
            # load the registry, compare it's offsets to file list, set offset to 0 for new files, process the whole list and if finished within the interval wait for next loop,
            # TODO: sort by timestamp ?
            #filelist.sort_by(|k,v|resource(k)[:date])
            filelist.clear

            # Listing all the files
            filelist = list_blobs(false)
            if (@debug_until > @processed) then
                @registry.each do |name, file|
                    @logger.info("#{name} offset: #{file[:offset]} length: #{file[:length]}")
                end
            end
            filelist.each do |name, file|
                off = 0
                if @registry.key?(name) then
                    begin
                        off = @registry[name][:offset]
                    rescue Exception => e
                        @logger.error("caught: #{e.message} while reading #{name}")
                    end
                end
                @registry.store(name, { :offset => off, :length => file[:length] })
                if (@debug_until > @processed) then @logger.info("2: adding offsets: #{name} #{off} #{file[:length]}") end
            end

            # clean registry of files that are not in the filelist
            @registry.each do |name,file|
                unless filelist.include?(name)
                    @registry.delete(name)
                    if (@debug_until > @processed) then @logger.info("purging #{name}") end
                end
            end

            # Worklist is the subset of files where the already read offset is smaller than the file size
            worklist.clear
            chunk = nil

            worklist = @registry.select {|name,file| file[:offset] < file[:length]}
            if (worklist.size > 4) then @logger.info("worklist contains #{worklist.size} blobs") end

            # Start of processing
            # This would be ideal for threading since it's IO intensive, would be nice with a ruby native ThreadPool
            # pool = Concurrent::FixedThreadPool.new(5) # 5 threads
            #pool.post do
            # some parallel work
            #end
            if (worklist.size > 0) then
                worklist.each do |name, file|
                    start = Time.now.to_i
                    if (@debug_until > @processed) then @logger.info("3: processing #{name} from #{file[:offset]} to #{file[:length]}") end
                    size = 0
                    if file[:offset] == 0
                        # length and skip reg value
                        if (file[:length] > 0)
                            begin
                                chunk = full_read(name)
                                delta_size = chunk.size
                            rescue Exception => e
                                # Azure::Core::Http::HTTPError / undefined method `message='
                                @logger.error("Failed to read #{name} ... will continue, set file as read and pretend this never happened")
                                @logger.error("#{size} size and #{file[:length]} file length")
                                chunk = nil
                                delta_size = file[:length]
                            end
                        else
                            @logger.info("found a zero size file #{name}")
                            chunk = nil
                            delta_size = 0
                        end
                    else
                        chunk = partial_read(name, file[:offset])
                        delta_size = chunk.size - @head.length - 1
                    end

                    #
                    # TODO! ... split out the logtypes and use individual methods
                    # how does a byte array chuck from json_lines get translated to strings/json/events
                    # should the byte array be converted to a multiline and then split? drawback need to know characterset and linefeed characters
                    # how does the json_line decoder work on byte arrays?
                    #
                    # so many questions

                    unless chunk.nil?
                    counter = 0
                        if @is_json
                            if logtype == "nsgflowlog"
                                res = resource(name)
                                begin
                                    fingjson = JSON.parse(chunk)
                                    @processed += nsgflowlog(queue, fingjson, name)
                                    @logger.debug("Processed #{res[:nsg]} #{@processed} events")
                                rescue JSON::ParserError => e
                                    @logger.error("parse error #{e.message} on #{res[:nsg]} offset: #{file[:offset]} length: #{file[:length]}")
                                    if (@debug_until > @processed) then @logger.info("#{chunk}") end
                                end
                            else
                                begin
                                    @codec.decode(chunk) do |event|
                                        counter += 1
                                        if @addfilename
                                            event.set('filename', name)
                                        end
                                        decorate(event)
                                        queue << event
                                     end
                                     @processed += counter
                                 rescue Exception => e
                                     @logger.error("codec exception: #{e.message} .. continue and pretend this never happened")
                                 end
                             end
                          end

                        if logtype == "wadiis" && !@is_json
                            # TODO: Convert this to line based grokking.
                            @processed += wadiislog(queue, name)
                        end

                        if @is_json_line
                            # parse one line at a time and dump it in the chunk?
                            lines = chunk.to_s
                            if cleanjson
                                @logger.info("cleaning in progress")
                                lines.chars.select(&:valid_encoding?).join
                                #lines.delete "\\"
                                #lines.scrub{|bytes| '<'+bytes.unpack('H*')[0]+'>' }
                            end
                            begin
                                @codec.decode(lines) do |event|
                                    counter += 1
                                    queue << event
                                end
                                @processed += counter
                            rescue Exception => e
                                # todo: fix codec_lines exception: no implicit conversion of Array into String
                                @logger.error("json_lines codec exception: #{e.message} .. continue and pretend this never happened")
                            end
                        end

                        if !@is_json_line && !@is_json
                            if logtype == "wadiis"
                                # TODO: Convert this to line based grokking.
                                @processed += wadiislog(queue, name)
                            else
                                # Any other codec and logstyle
                                begin
                                    @codec.decode(chunk) do |event|
                                        counter += 1
                                        if @addfilename
                                            event.set('filename', name)
                                        end
                                        queue << event
                                    end
                                    @processed += counter
                                rescue Exception => e
                                @logger.error("other codec exception: #{e.message} .. continue and pretend this never happened")
                                end
                            end
                        end
                    end

                    # Update the size
                    size = file[:offset] + delta_size
                    @registry.store(name, { :offset => size, :length => file[:length] })

                    #@logger.info("name #{name} size #{size} len #{file[:length]}")
                    # if stop? good moment to stop what we're doing
                    if stop?
                        return
                    end
                    if ((Time.now.to_i - @last) > @interval)
                        save_registry()
                    end
                end
            end
            # The files that got processed after the last registry save need to be saved too, in case the worklist is empty for some intervals.
            now = Time.now.to_i
            if ((now - @last) > @interval)
                save_registry()
            end
            sleeptime = interval - ((now - start) % interval)
            if @debug_timer
                @logger.info("going to sleep for #{sleeptime} seconds")
            end
            Stud.stoppable_sleep(sleeptime) { stop? }
        end
    end

    def stop
        save_registry()
    end
    def close
        save_registry()
    end


private
    def list_files
        filelist = list_blobs(false)
        filelist.each do |name, file|
            off = 0
            if @registry.key?(name) then
                begin
                    off = @registry[name][:offset]
                rescue Exception => e
                    @logger.error("caught: #{e.message} while reading #{name}")
                end
            end
            @registry.store(name, { :offset => off, :length => file[:length] })
            if (@debug_until > @processed) then @logger.info("2: adding offsets: #{name} #{off} #{file[:length]}") end
        end
        return filelist
    end
    # size nilClass when the list doesn't grow?!

    def connect
        # Try in this order to access the storageaccount
        # 1. storageaccount / sas_token
        # 2. connection_string
        # 3. storageaccount / access_key

        unless connection_string.nil?
            conn = connection_string.value
        end
        unless sas_token.nil?
            unless sas_token.value.start_with?('?')
                conn = "BlobEndpoint=https://#{storageaccount}.#{dns_suffix};SharedAccessSignature=#{sas_token.value}"
            else
                conn = sas_token.value
            end
        end
        unless conn.nil?
            @blob_client = Azure::Storage::Blob::BlobService.create_from_connection_string(conn)
        else
            # unless use_development_storage?
            @blob_client = Azure::Storage::Blob::BlobService.create(
                storage_account_name: storageaccount,
                storage_dns_suffix: dns_suffix,
                storage_access_key: access_key.value,
            )
            # else
            #     @logger.info("development storage emulator not yet implemented")
            # end
        end
    end
    # @registry_create_policy,@registry_local_path,@container,@registry_path
    def load_registry()
        if @registry_create_policy == "resume"
            for counter in 1..3
                begin
                    if (!@registry_local_path.nil?)
                        unless File.file?(@registry_local_path+"/"+@pipe_id)
                            @registry = Marshal.load(@blob_client.get_blob(@container, path)[1])
                            #[0] headers [1] responsebody
                            @logger.info("migrating from remote registry #{path}")
                        else
                            if !Dir.exist?(@registry_local_path)
                                FileUtils.mkdir_p(@registry_local_path)
                            end
                            @registry = Marshal.load(File.read(@registry_local_path+"/"+@pipe_id))
                            @logger.info("resuming from local registry #{@registry_local_path+"/"+@pipe_id}")
                        end
                    else
                        @registry = Marshal.load(@blob_client.get_blob(container, path)[1])
                        #[0] headers [1] responsebody
                        @logger.info("resuming from remote registry #{path}")
                    end
                    break
                rescue Exception => e
                    @logger.error("caught: #{e.message}")
                    @registry.clear
                    @logger.error("loading registry failed for attempt #{counter} of 3")
                end
             end
        end
        # read filelist and set offsets to file length to mark all the old files as done
        if @registry_create_policy == "start_fresh"
            @registry = list_blobs(true)
            #save_registry()
            @logger.info("starting fresh, with a clean registry containing #{@registry.size} blobs/files")
        end
    end

    def full_read(filename)
        tries ||= 2
        begin
            return @blob_client.get_blob(@container, filename)[1]
        rescue Exception => e
            @logger.error("caught: #{e.message} for full_read")
            if (tries -= 1) > 0
                if e.message = "Connection reset by peer"
                    connect
                end
                retry
            end
        end
        begin
            chuck = @blob_client.get_blob(@container, filename)[1]
        end
        return chuck
    end

    def partial_read(blobname, offset)
        # 1. read committed blocks, calculate length
        # 2. calculate the offset to read
        # 3. strip comma
        # if json strip comma and fix head and tail
        size = 0

        begin
            if @append
                return @blob_client.get_blob(@container, blobname, start_range: offset-1)[1]
            end
            blocks = @blob_client.list_blob_blocks(@container, blobname)
            blocks[:committed].each do |block|
                size += block.size
            end
            # read the new blob blocks from the offset to the last committed size.
            # if it is json, fix the head and tail
            # crap committed block at the end is the tail, so must be substracted from the read and then comma stripped and tail added.
            # but why did I need a -1 for the length?? probably the offset starts at 0 and ends at size-1

            # should first check commit, read and the check committed again? no, only read the commited size
            # should read the full content and then substract json tail

            unless @is_json
                return @blob_client.get_blob(@container, blobname, start_range: offset, end_range: size-1)[1]
            else
                content = @blob_client.get_blob(@container, blobname, start_range: offset-1, end_range: size-1)[1]
                if content.end_with?(@tail)
                    return @head + strip_comma(content)
                else
                    @logger.info("Fixed a tail! probably new committed blocks started appearing!")
                    # substract the length of the tail and add the tail, because the file grew.size was calculated as the block boundary, so replacing the last bytes with the tail should fix the problem 
                    return @head + strip_comma(content[0...-@tail.length]) + @tail
                end
            end
        rescue InvalidBlobType => ibt
            @logger.error("caught #{ibt.message}. Setting BlobType to append")
            @append = true
            retry
        rescue NoMethodError => nme
            @logger.error("caught #{nme.message}. Setting append to true")
            @append = true
            retry
        rescue Exception => e
            @logger.error("caught #{e.message}")
        end
    end

    def strip_comma(str)
        # when skipping over the first blocks the json will start with a comma that needs to be stripped. there should not be a trailing comma, but it gets stripped too
        if str.start_with?(',')
            str[0] = ''
        end
        str.nil? ? nil : str.chomp(",")
    end


    def nsgflowlog(queue, json, name)
        count=0
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

                            # Add event to logstash queue
                            event = LogStash::Event.new('message' => ev.to_json)
                            #if @ecs_compatibility != "disabled"
                            #    event = ecs(event)
                            #end
                            decorate(event)
                            queue << event
                            count+=1
                        end
                    end
                end
            end
        rescue Exception => e
            @logger.error("NSG Flowlog problem for #{name} and error message #{e.message}")
        end
        return count
    end

    def wadiislog(lines)
        count=0
        lines.each do |line|
            unless line.start_with?('#')
                queue << LogStash::Event.new('message' => ev.to_json)
                count+=1
            end
        end
        return count
        # date {
        #   match => [ "log_timestamp", "YYYY-MM-dd HH:mm:ss" ]
        #   target => "@timestamp"
        #   remove_field => ["log_timestamp"]
        # }
    end

    # list all blobs in the blobstore, set the offsets from the registry and return the filelist
    # inspired by: https://github.com/Azure-Samples/storage-blobs-ruby-quickstart/blob/master/example.rb
    def list_blobs(fill)
        tries ||= 3
        begin
            return try_list_blobs(fill)
        rescue Exception => e
            @logger.error("caught: #{e.message} for list_blobs retries left #{tries}")
            if (tries -= 1) > 0
                retry
            end
        end
    end

    def try_list_blobs(fill)
        # inspired by: http://blog.mirthlab.com/2012/05/25/cleanly-retrying-blocks-of-code-after-an-exception-in-ruby/
        chrono = Time.now.to_i
        files = Hash.new
        nextMarker = nil
        counter = 1
        loop do
            begin
                blobs = @blob_client.list_blobs(@container, { marker: nextMarker, prefix: @prefix})
                blobs.each do |blob|
                    # FNM_PATHNAME is required so that "**/test" can match "test" at the root folder
                    # FNM_EXTGLOB allows you to use "test{a,b,c}" to match either "testa", "testb" or "testc" (closer to shell behavior)
                    unless blob.name == registry_path
                        if @path_filters.any? {|path| File.fnmatch?(path, blob.name, File::FNM_PATHNAME | File::FNM_EXTGLOB)}
                            length = blob.properties[:content_length].to_i
                            offset = 0
                            if fill
                                offset = length
                            end
                            files.store(blob.name, { :offset => offset, :length => length })
                            if (@debug_until > @processed) then @logger.info("1: list_blobs #{blob.name} #{offset} #{length}") end
                        end
                    end
                end
                nextMarker = blobs.continuation_token
                break unless nextMarker && !nextMarker.empty?
                if (counter % 10 == 0) then @logger.info(" listing #{counter * 50000} files") end
                counter+=1
            rescue Exception => e
                @logger.error("caught: #{e.message} while trying to list blobs")
                return files
            end
        end
        if @debug_timer
            @logger.info("list_blobs took #{Time.now.to_i - chrono} sec")
        end
        return files
    end

    # When events were processed after the last registry save, start a thread to update the registry file.
    def save_registry()
        unless @processed == @regsaved
            unless (@busy_writing_registry.locked?)
                # deep_copy hash, to save the registry independant from the variable for thread safety
                # if deep_clone uses Marshall to do a copy,
                regdump = Marshal.dump(@registry)
                regsize = @registry.size
                Thread.new {
                    begin
                        @busy_writing_registry.lock
                        unless (@registry_local_path)
                            @blob_client.create_block_blob(@container, registry_path, regdump)
                            @logger.info("processed #{@processed} events, saving #{regsize} blobs and offsets to remote registry #{registry_path}")
                        else
                            File.open(@registry_local_path+"/"+@pipe_id, 'w') { |file| file.write(regdump) }
                            @logger.info("processed #{@processed} events, saving #{regsize} blobs and offsets to local registry #{registry_local_path+"/"+@pipe_id}")
                        end
                        @last = Time.now.to_i
                        @regsaved = @processed
                    rescue Exception => e
                        @logger.error("Oh my, registry write failed")
                        @logger.error("#{e.message}")
                    ensure
                        @busy_writing_registry.unlock
                    end
                }
            else
                @logger.info("Skipped writing the registry because previous write still in progress, it just takes long or may be hanging!")
            end
        end
    end


    def learn_encapsulation
        @logger.info("learn_encapsulation, this can be skipped by setting skip_learning => true. Or set both head_file and tail_file")
        # From one file, read first block and last block to learn head and tail
        begin
            blobs = @blob_client.list_blobs(@container, { max_results: 3, prefix: @prefix})
            blobs.each do |blob|
                unless blob.name == registry_path
                    begin
                        blocks = @blob_client.list_blob_blocks(@container, blob.name)[:committed]
                        if ['A00000000000000000000000000000000','QTAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'].include?(blocks.first.name)
                            @logger.debug("using #{blob.name}/#{blocks.first.name} to learn the json header")
                            @head = @blob_client.get_blob(@container, blob.name, start_range: 0, end_range: blocks.first.size-1)[1]
                        end
                        if ['Z00000000000000000000000000000000','WjAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw'].include?(blocks.last.name)
                            @logger.debug("using #{blob.name}/#{blocks.last.name} to learn the json footer")
                            length = blob.properties[:content_length].to_i
                            offset = length - blocks.last.size
                            @tail = @blob_client.get_blob(@container, blob.name, start_range: offset, end_range: length-1)[1]
                            @logger.debug("learned tail: #{@tail}")
                        end
                    rescue Exception => e
                        @logger.info("learn json one of the attempts failed")
                    end
                end
            end
        rescue Exception => e
            @logger.info("learn json header and footer failed because #{e.message}")
        end
    end

    def resource(str)
        temp = str.split('/')
        #date = '---'
        #unless temp[9].nil?
        #    date = val(temp[9])+'/'+val(temp[10])+'/'+val(temp[11])+'-'+val(temp[12])+':00'
        #end
        return {:subscription=> temp[2], :resourcegroup=>temp[4], :nsg=>temp[8]}
    end

    def val(str)
        return str.split('=')[1]
    end
end # class LogStash::Inputs::AzureBlobStorage

# This is a start towards mapping NSG events to ECS fields ... it's complicated
=begin
    def ecs(old)
        # https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
        ecs = LogStash::Event.new()
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
    end
=end
