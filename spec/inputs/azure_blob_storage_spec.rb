# encoding: utf-8
require "logstash/devutils/rspec/spec_helper"
require "logstash/inputs/azure_blob_storage"

describe LogStash::Inputs::AzureBlobStorage do

  it_behaves_like "an interruptible input plugin" do
    let(:config) { { "interval" => 100 } }
  end

  def test_helper_methodes 
      assert_equal('b', AzureBlobStorage.val('a=b'))
      assert_equal('whatever', AzureBlobStorage.strip_comma(',whatever'))
      assert_equal('whatever', AzureBlobStorage.strip_comma('whatever,'))
      assert_equal('whatever', AzureBlobStorage.strip_comma(',whatever,'))
      assert_equal('whatever', AzureBlobStorage.strip_comma('whatever'))
  end
end
