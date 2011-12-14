$:.unshift(File.join(__FILE__, '..', "OriginalAWS"))
require 'OriginalAWS/EC3'

module AWS
  class EC3
    def initialize(*args)
      @ec3 = ::EC3.new(*args)
    end

    def method_missing(key, *args)
      @ec3.send(key, *args)
    end
  end
end
