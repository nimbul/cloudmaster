$:.unshift(File.join(__FILE__, '..', "OriginalAWS"))
require 'OriginalAWS/SQS'

module AWS
  class SQS
    def initialize(*args)
      @sqs = ::SQS.new(*args)
    end

    def method_missing(key, *args)
      @sqs.send(key, *args)
    end
  end
end
