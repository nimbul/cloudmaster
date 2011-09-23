Gem::Specification.new do |s|
  s.specification_version = 2 if s.respond_to? :specification_version=
  s.required_rubygems_version = Gem::Requirement.new(">= 0") if s.respond_to? :required_rubygems_version=


  s.version       = '1.0.0'
  s.name          = 'cloudmaster'
  #s.version      = '2.4.1'
  s.date          = '2011-09-23'

  s.authors       = ['Vadim Jelezniakov']
  s.summary       = "AWS Libraries for Ruby."

  s.require_paths = %w[lib]
  s.bindir        = 'tools'
end

