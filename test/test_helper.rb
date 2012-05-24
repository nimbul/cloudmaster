$LOAD_PATH.unshift File.expand_path(File.join(File.dirname(__FILE__), '..', 'app'))
$LOAD_PATH.unshift File.expand_path(File.join(File.dirname(__FILE__), '..', 'lib'))

require 'test/unit'
require 'rr'

class Test::Unit::TestCase
  include RR::Adapters::TestUnit
end
