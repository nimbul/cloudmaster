#
# This module adds aws_object class method that in turn adds the following instance methods
# for any AWS object
#   parse_<aws_object_class> elem
#   parse_<aws_object_class>s xml_doc
#   create_<aws_object_class> options
#   describe_<aws_object_class>s [names]
#   delete_<aws_object_class> name   
#
module AwsApiActions
  def self.included(base)
    base.extend(ClassMethods)
    base.class_eval do
      include AWS # Include the AWS module as a mixin
      include AwsInflector
      include InstanceMethods
    end
  end
  
  module ClassMethods
    API_VERSION = '2009-05-15'
    SIGNATURE_VERSION = '1'
    HTTP_METHOD = 'POST' # 'GET' #
    def aws_object(*args)
      args.each do |arg|
        klass = camelize(arg.to_s)
        parser = parserize(klass)
        create_parser = 'Create'+camelize(arg.to_s)+'ResultParser'
        delete_parser = 'Delete'+camelize(arg.to_s)+'ResultParser'
        define_method("create_#{arg}") do |options|
          endpoint_uri = self.class.constantize(parser).endpoint_uri
          ps = {
            'Action' => "Create#{klass}",
          }

          object = self.class.constantize(parser).new(options)
          ps.merge!(object.to_parameters) unless object.nil?

          parameters = build_query_params(API_VERSION, SIGNATURE_VERSION, ps)
          response = do_query(HTTP_METHOD, endpoint_uri, parameters)
          result = REXML::Document.new(response.body)

          # try to return a result object
          begin
            result = self.class.constantize(create_parser).parse_xml(result)[0]
          rescue
          end

          return result
        end
        define_method("describe_#{arg}s") do
          endpoint_uri = self.class.constantize(parser).endpoint_uri
          ps = {
            'Action' => "Describe#{klass}s",
            'MaxRecords' => 100,
          }

          parameters = build_query_params(API_VERSION, SIGNATURE_VERSION, ps)
          response = do_query(HTTP_METHOD, endpoint_uri, parameters)
          xml_doc = REXML::Document.new(response.body)

          self.class.constantize(parser).parse_xml xml_doc
        end
        define_method("delete_#{arg}") do |name|
          endpoint_uri = self.class.constantize(parser).endpoint_uri
          ps = {
            'Action' => "Delete#{klass}",
            "#{klass}Name" => name,
          }

          parameters = build_query_params(API_VERSION, SIGNATURE_VERSION, ps)
          response = do_query(HTTP_METHOD, endpoint_uri, parameters)
          result = REXML::Document.new(response.body)

          # try to return a result object
          begin
            result = self.class.constantize(delete_parser).parse_xml(result)[0]
          rescue
          end

          return result
        end
      end
    end
  end
  
  module InstanceMethods
  end
end