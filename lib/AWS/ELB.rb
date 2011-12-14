$:.unshift(File.join(ENV['AWS_HOME'], "lib", "OriginalAWS"))
require 'OriginalAWS/ELB'

module AWS
  class ELB
    def initialize(*args)
      @elb = ::ELB.new(*args)
    end

    def method_missing(key, *args)
      @elb.send(key, *args)
    end
  end
end
