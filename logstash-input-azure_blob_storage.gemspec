Gem::Specification.new do |s|
  s.name          = 'logstash-input-azure_blob_storage'
  s.version       = '0.10.2'
  s.licenses      = ['Apache-2.0']
  s.summary       = 'This logstash plugin reads and parses data from Azure Storage Blobs.'
  s.description   = <<-EOF
 This gem is a Logstash plugin. It reads and parses data from Azure Storage Blobs. The azure_blob_storage is a reimplementation to replace azureblob from azure-diagnostics-tools/Logstash. It can deal with larger volumes and partial file reads and eliminating a delay when rebuilding the registry.

 The minimal logstash pipeline configuration would look like this
> input {
>   azure_blob_storage {
>       storageaccount => "yourstorageaccountname"
>       access_key => "Ba5e64c0d3=="
>       container => "insights-logs-networksecuritygroupflowevent"
>   }
> }
EOF
  s.homepage      = 'https://github.com/janmg/logstash-input-azure_blob_storage'
  s.authors       = ['Jan Geertsma']
  s.email         = 'jan@janmg.com'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "input" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_runtime_dependency 'logstash-codec-plain', '~> 3.0'
  s.add_runtime_dependency 'stud', '~> 0.0.22'
  s.add_runtime_dependency 'azure-storage-blob', '~> 1.0'
  s.add_development_dependency 'logstash-devutils', '~> 1.0', '>= 1.0.0'
end
