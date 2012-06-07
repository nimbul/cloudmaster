require 'nokogiri'

# Sample Ruby code for the O'Reilly book "Programming Amazon Web
# Services" by James Murty.
#
# This code was written for Ruby version 1.8.6 or greater.
#
# The EC2 module implements the Query API of the Amazon Elastic Compute Cloud
# service.
#
# Extended by Charles Hayden to cover EBS interface extensions.
require 'AWS/AWS'

class EC2
  include AWS # Include the AWS module as a mixin

  ENDPOINT_URI = URI.parse("https://ec2.amazonaws.com/")
  #API_VERSION = '2009-08-15'
  API_VERSION = '2011-05-15'
  SIGNATURE_VERSION = '2'

  HTTP_METHOD = 'POST' # 'GET'

  def parse_reserved_instance(elem)
    ##  The element may come in at the fragment level or the document level
    elem = elem.at('item') if elem.kind_of? Nokogiri::XML::Document
    Hash[
      elem.children.collect { |c|
        case c.name
          when 'reservedInstancesId'  then [ :reserved_instances_id, c.text ]
          when 'instanceType'         then [ :instance_type        , c.text ]
          when 'availabilityZone'     then [ :zone                 , c.text ]
          when 'start'                then [ :start                , c.text ]
          when 'duration'             then [ :duration             , c.text ]
          when 'fixedPrice'           then [ :fixed_price          , c.text ]
          when 'usagePrice'           then [ :usage_price          , c.text ]
          when 'instanceCount'        then [ :count                , c.text ]
          when 'productDescription'   then [ :description          , c.text ]
          when 'state'                then [ :state                , c.text ]
        end
      }
    ]
  end

  def parse_reservation(elem)
    reservation = {
      :reservation_id => elem.xpath('item/reservationId|./reservationId').first.text,
      :owner_id => elem.xpath('item/ownerId|./ownerId').first.text,
    }

    reservation[:groups] = elem.xpath('item/groupSet//groupId|./groupSet//groupId').collect do |group|
      group.text
    end

    map = Proc.new { |el, target|
                    case el.name
                      when 'instanceId'       then [ :id               , el.text ]
                      when 'imageId'          then [ :image_id         , el.text ]
                      when 'instanceState'    then [ :state, el.children.find { |c| c.name == 'name' }.text ]
                      when 'privateDnsName'   then [ :private_dns      , el.text ]
                      when 'dnsName'          then [ :public_dns       , el.text ]
                      when 'reason'           then [ :reason           , el.text ]
                      when 'keyName'          then [ :key_name         , el.text ]
                      when 'amiLaunchIndex'   then [ :index            , el.text ]
                      when 'productCodes'
                        target[:product_codes] ||= []
                        el.children.map { |el| target[:product_codes] << el.text }
                        [nil, nil]
                      when 'instanceType'     then [ :type             , el.text ]
                      when 'launchTime'       then [ :launch_time      , el.text ]
                      when 'placement'        then [ :zone, el.children.find { |c| c.name == 'availabilityZone' }.text ]
                      when 'kernelId'         then [ :kernel_id        , el.text ]
                      when 'ramdiskId'        then [ :ramdisk_id       , el.text ]
                      when 'platform'         then [ :platform         , el.text ]
                      when 'monitoring'       then [ :monitoring       , el.children.find { |c| c.name == 'state' }.text ]
                      when 'subnetId'         then [ :subnet_id        , el.text ]
                      when 'vpcId'            then [ :vpc_id           , el.text ]
                      when 'privateIpAddress' then [ :private_ip       , el.text ]
                      when 'ipAddress'        then [ :public_ip        , el.text ]
                      when 'architecture'     then [ :architecture     , el.text ]
                      when 'rootDeviceType'   then [ :root_device_type , el.text ]
                      when 'rootDeviceName'   then [ :root_device_name , el.text ]
                      else                         [ nil               , nil     ]
                    end
                  }

    instances_node = elem.xpath('item/instancesSet/item|./instancesSet/item')
    reservation[:instances] = instances_node.collect do |instance|
      item = Hash.new
      instance.children.each do |el|
        item.store( *map.call(el, item) )
      end
      item.delete nil
      item
    end

    return reservation
  end

  def parse_volume(elem)
    elem = elem.at('item') if elem.kind_of? Nokogiri::XML::Document
    attachment_element = nil
    volume = \
    Hash[ elem.children.collect { |c|
      case c.name
      when 'volumeId' then [ :volume_id, c.text ]
      when 'size' then [ :size, c.text ]
      when 'status' then [ :status, c.text ]
      when 'createTime' then [ :create_time, c.text ]
      when 'snapshotId' then [ :snapshot_id, c.text ]
      when 'availabilityZone' then [ :availability_zone, c.text ]
      when 'attachmentSet' 
        attachment_element = c
        nil
      end
    }]

    volume[:attachment_set] = attachment_element.children.collect { |item|
      Hash[
        item.children.collect { |c|
          case c.name
          when 'volumeId' then [:volume_id, c.text]
          when 'instanceId' then [:instance_id, c.text]
          when 'device' then [:device, c.text]
          when 'status' then [:status, c.text]
          when 'attachTime' then [:attach_time, c.text]
          end
        }
      ]
    }
    return volume
  end

  def describe_instances(*instance_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeInstances',
      },{
      'InstanceId' => instance_ids
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    reservations = []
    xml_doc.search('reservationSet/item').each do |elem|
      reservations << parse_reservation(elem)
    end
    return reservations
  end

  def describe_reserved_instances(*instance_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeReservedInstances',
      },{
      'ReservedInstancesId' => instance_ids
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    instances = []
    xml_doc.search('reservedInstancesSet/item').each do |elem|
      instances << parse_reserved_instance(elem)
    end
    return instances
  end

  def describe_availability_zones(region = nil)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeAvailabilityZones',
      }
    )
    endpoint_uri = ENDPOINT_URI
    unless region.nil?
        regions = describe_regions(region)
        endpoint = regions[0][:endpoint]
        endpoint_uri = URI.parse("https://#{endpoint}/")
    end

    response = do_query(HTTP_METHOD, endpoint_uri, parameters)
    xml_doc = parse_xml(response.body)

    zones = []
    xml_doc.search('availabilityZoneInfo/item').each do |elem|
      zones << {
        :name => elem.at('zoneName').text,
        :state => elem.at('zoneState').text
      }
    end
    return zones
  end

  def describe_regions(*names)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeRegions',
      },{
      'RegionName' => names
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    regions = []
    xml_doc.search('regionInfo/item').each do |elem|
      regions << {
        :name => elem.at('regionName').text,
        :endpoint => elem.at('regionEndpoint').text
      }
    end
    return regions
  end

  def describe_keypairs(*keypair_names)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeKeyPairs',
      },{
      'KeyName' => keypair_names
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    keypairs = []
    xml_doc.search('keySet/item').each do |key|
      keypairs << {
        :name => key.at('keyName').text,
        :fingerprint => key.at('keyFingerprint').text
      }
    end

    return keypairs
  end

  def create_keypair(keyname, autosave=true)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'CreateKeyPair',
      'KeyName' => keyname,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    keypair = {
      :name => xml_doc.at('keyName').text,
      :fingerprint => xml_doc.at('keyFingerprint').text,
      :material => xml_doc.at('keyMaterial').text
    }

    if autosave
      # Locate key material and save to a file named after the keyName
      File.open("#{keypair[:name]}.pem",'w') do |file|
        file.write(keypair[:material] + "\n")
        keypair[:file_name] = file.path
      end
    end

    return keypair
  end

  def delete_keypair(keyname)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DeleteKeyPair',
      'KeyName' => keyname,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def describe_images(options={})
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeImages',
      # Despite API documentation, the ImageType parameter is *not* supported, see:
      # http://developer.amazonwebservices.com/connect/thread.jspa?threadID=20655&tstart=25
      # 'ImageType' => options[:type]
      },{
      'ImageId' => options[:image_ids],
      'Owner' => options[:owners],
      'ExecutableBy' => options[:executable_by]
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    xml_doc.children.collect { |response|
      response.children.select { |x| x.name == 'imagesSet' }.collect { |imageset|
        imageset.children.collect { |item|
          Hash[item.children.collect { |i|
            case i.name
              when 'imageId'        then [ :id               , i.text           ]
              when 'imageLocation'  then [ :location         , i.text           ]
              when 'imageState'     then [ :state            , i.text           ]
              when 'imageOwnerId'   then [ :owner_id         , i.text           ]
              when 'isPublic'       then [ :is_public        , i.text == 'true' ]
              when 'architecture'   then [ :architecture     , i.text           ]
              when 'imageType'      then [ :type             , i.text           ]
              when 'name'           then [ :name             , i.text           ]
              when 'description'    then [ :description      , i.text           ]
              when 'rootDeviceName' then [ :root_device_name , i.text           ]
              when 'rootDeviceType' then [ :root_device_type , i.text           ]
              when 'kernelId'       then [ :kernel_id        , i.text           ]
              when 'ramdiskId'      then [ :ramdisk_id       , i.text           ]
              when 'blockDeviceMapping'
                [
                  :block_device_mapping,
                  i.children.collect { |dev|
                    h = Hash[ dev.children.collect { |x|
                      case x.name
                      when 'deviceName'  then [ :device_name  , x.text                    ]
                      when 'virtualName' then [ :virtual_name , x.text                    ]
                      when 'noDevice'    then [ :no_device    , x.text.nil ? true : false ]
                      when 'ebs'
                        [
                          :ebs,
                          Hash[ x.children.collect { |ebs|
                            case ebs.name
                              when 'snapshotId'          then [ :snapshot_id           , ebs.text  ]
                              when 'volumeSize'          then [ :volume_size           , ebs.text  ]
                              when 'deleteOnTermination' then [ :delete_on_termination , ebs.text == "true" ]
                            end
                          }]
                        ]
                      end
                    }]
                    h[:no_device] = h.fetch(:no_device, false)
                    h
                  }
                ]
              end
            }
          ]
        }.flatten
      }.flatten
    }.flatten
  end

  def run_instances(image_id, min_count=1, max_count=min_count, options={})
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'RunInstances',
      'ImageId' => image_id,
      'MinCount' => min_count,
      'MaxCount' => max_count,
      'KeyName' => options[:key_name],
      'InstanceType' => options[:instance_type],
      'UserData' => encode_base64(options[:user_data]),
      'Placement.AvailabilityZone' => options[:zone],
      'KernelId' => options[:kernel_id],
      'RamdiskId' => options[:ramdisk_id]
      },{
      'SecurityGroup' => options[:security_groups]
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return parse_reservation(xml_doc.root)
  end

  def terminate_instances(*instance_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'TerminateInstances',
      },{
      'InstanceId' => instance_ids,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    instances = []
    xml_doc.search('instancesSet/item').each do |item|
      instances << {
        :id => item.at('instanceId').text,
        :state => item.at('currentState/name').text,
        :previous_state => item.at('previousState/name').text
      }
    end

    return instances
  end

  def stop_instances(instance_ids, force=nil)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'StopInstances',
      'Force' => force,
      },{
      'InstanceId' => instance_ids,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    instances = []
    xml_doc.search('instancesSet/item').each do |item|
      instances << {
        :id => item.at('instanceId').text,
        :state => item.at('currentState/name').text,
        :previous_state => item.at('previousState/name').text
      }
    end

    return instances
  end

  def start_instances(instance_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'StartInstances',
      },{
      'InstanceId' => instance_ids,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    instances = []
    xml_doc.search('instancesSet/item').each do |item|
      instances << {
        :id => item.at('instanceId').text,
        :state => item.at('currentState/name').text,
        :previous_state => item.at('previousState/name').text
      }
    end

    return instances
  end

  def authorize_ingress_by_cidr(group_name, ip_protocol, from_port,
                              to_port=from_port, cidr_range='0.0.0.0/0')

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'AuthorizeSecurityGroupIngress',
      'GroupName' => group_name,
      'IpProtocol' => ip_protocol,
      'FromPort' => from_port,
      'ToPort' => to_port,
      'CidrIp' => cidr_range,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def authorize_ingress_by_group(group_name, source_security_group_name,
                                 source_security_group_owner_id)

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'AuthorizeSecurityGroupIngress',
      'GroupName' => group_name,
      'SourceSecurityGroupName' => source_security_group_name,
      'SourceSecurityGroupOwnerId' => source_security_group_owner_id,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)

    return true
  end

  def describe_security_groups(*security_group_names)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeSecurityGroups',
      },{
      'GroupName' => security_group_names,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    security_groups = []
    xml_doc.search('securityGroupInfo/item').each do |sec_group|
      grants = []
      sec_group.search('ipPermissions/item').each do |item|
        grant = {}
        grant[:protocol] = item.at('ipProtocol').text if item.elements.at('ipProtocol')
        grant[:from_port] = item.at('fromPort').text if item.elements.at('fromPort')
        grant[:to_port] = item.at('toPort').text if item.elements.at('toPort')

        item.search('groups/item').each do |group|
          g = {}
          g[:user_id] = group.at('userId').text if group.elements.at('userId')
          g[:name] = group.at('groupName').text if group.elements.at('groupName')
          (grant[:groups] ||= []) << g
        end

        item.search('ipRanges/item').each do |iprange|
          (grant[:ip_range] ||= []) << iprange.at('cidrIp').text
        end

        grants << grant
      end

      security_groups << {
        :group_id => sec_group.at('groupId').text,
        :name => sec_group.at('groupName').text,
        :description => sec_group.at('groupDescription').text,
        :owner_id => sec_group.at('ownerId').text,
        :grants => grants
      }
    end

    return security_groups
  end

  def revoke_ingress_by_cidr(group_name, ip_protocol, from_port,
                             to_port=from_port, cidr_range='0.0.0.0/0')

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'RevokeSecurityGroupIngress',
      'GroupName' => group_name,
      'IpProtocol' => ip_protocol,
      'FromPort' => from_port,
      'ToPort' => to_port,
      'CidrIp' => cidr_range,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def revoke_ingress_by_group(group_name, source_security_group_name,
                              source_security_group_owner_id)

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'RevokeSecurityGroupIngress',
      'GroupName' => group_name,
      'SourceSecurityGroupName' => source_security_group_name,
      'SourceSecurityGroupOwnerId' => source_security_group_owner_id,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def create_security_group(group_name, group_description=group_name, vpc_id=nil)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'CreateSecurityGroup',
      'GroupName' => group_name,
      'GroupDescription' => group_description,
      })
    parameters['VpcId'] = vpc_id

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    group = {
      :group_id => xml_doc.at('groupId').text,
      :return => (xml_doc.at('return').text == 'true'),
    }

    return group
  end

  def delete_security_group(group_name)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DeleteSecurityGroup',
      'GroupName' => group_name,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end


  def register_image(image_location, options={})
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'RegisterImage',
      'ImageLocation' => image_location,
      'Name' => options[:name],
      'Description' => options[:description],
      'Architecture' => options[:architecture],
      'KernelId' => options[:kernel_id],
      'RamdiskId' => options[:ramdisk_id],
      'RootDeviceName' => options[:root_device_name],
      'BlockDeviceMapping' => options[:block_device_mapping],
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    return xml_doc.at('imageId').text
  end

  def deregister_image(image_id)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DeregisterImage',
      'ImageId' => image_id,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def describe_image_attribute(image_id, attribute='launchPermission')
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeImageAttribute',
      'ImageId' => image_id,
      'Attribute' => attribute,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    result = {:id => xml_doc.at('imageId').text}

    if xml_doc.at('launchPermission')
      result[:launch_perms_user] = []
      result[:launch_perms_group] = []
      xml_doc.search('launchPermission/item').each do |lp|
        elems = lp.elements
        result[:launch_perms_group] << elems.at('group').text if elems.at('group')
        result[:launch_perms_user] << elems.at('userId').text if elems.at('userId')
      end
    end

    if xml_doc.at('productCodes')
      result[:product_codes] = []
      xml_doc.search('productCodes/item').each do |pc|
        result[:product_codes] << pc.text
      end
    end

    return result
  end

  def modify_image_attribute(image_id, attribute,
                             operation_type, attribute_values)

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ModifyImageAttribute',
      'ImageId' => image_id,
      'Attribute' => attribute,
      'OperationType' => operation_type,
      }, attribute_values)

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def reset_image_attribute(image_id, attribute='launchPermission')
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ResetImageAttribute',
      'ImageId' => image_id,
      'Attribute' => attribute,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  def get_console_output(instance_id)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'GetConsoleOutput',
      'InstanceId' => instance_id,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    elems = parse_xml(response.body).elements

    return {
      :id => elems.at('instanceId').text,
      :timestamp => elems.at('timestamp').text,
      :output => Base64.decode64(elems.at('output').text).strip
    }
  end

  def reboot_instances(*instance_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'RebootInstances',
      },{
      'InstanceId' => instance_ids,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end


  def confirm_product_instance(product_code, instance_id)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ConfirmProductInstance',
      'ProductCode' => product_code,
      'InstanceId' => instance_id
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    elems = parse_xml(response.body).elements

    result = {
      :result => elems.at('result').text == true
    }
    result[:owner_id] = elems.at('ownerId').text if elems.at('ownerId')
    return result
  end

  def describe_addresses(*addresses)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeAddresses',
      },{
      'PublicIp' => addresses
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    addresses = []
    xml_doc.search('addressesSet/item').each do |elem|
      addresses << {
        :public_ip => elem.at('publicIp').text,
        :instance_id => elem.at('instanceId').text
      }
    end
    return addresses
  end
  
  def allocate_address()
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'AllocateAddress',
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('publicIp').text
  end

  def release_address(public_ip)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ReleaseAddress',
      'PublicIp' => public_ip
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def associate_address(instance_id, public_ip)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'AssociateAddress',
      'InstanceId' => instance_id,
      'PublicIp' => public_ip
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def disassociate_address(public_ip)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DisassociateAddress',
      'PublicIp' => public_ip
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def create_volume(size, availability_zone)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'CreateVolume',
      'Size' => size,
      'AvailabilityZone' => availability_zone
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    res = {}
    res[:volume_id] = xml_doc.at('volumeId').text
    res[:size] = xml_doc.at('size').text
    res[:status] = xml_doc.at('status').text
    res[:create_time] = xml_doc.at('createTime').text
    res[:availability_zone] = xml_doc.at('availabilityZone').text
    res[:snapshot_id] = xml_doc.at('snapshotId').text
    res
  end

  def create_volume_from_snapshot(snapshot_id, availability_zone)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'CreateVolume',
      'SnapshotId' => snapshot_id,
      'AvailabilityZone' => availability_zone
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    res = {}
    res[:volume_id] = xml_doc.at('volumeId').text
    res[:size] = xml_doc.at('size').text
    res[:status] = xml_doc.at('status').text
    res[:create_time] = xml_doc.at('createTime').text
    res[:availability_zone] = xml_doc.at('availabilityZone').text
    res[:snapshot_id] = xml_doc.at('snapshotId').text
    res
  end

  def delete_volume(volume_id)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DeleteVolume',
      'VolumeId' => volume_id
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def describe_volumes(*volume_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeVolumes',
      },{
      'VolumeId' => volume_ids
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    volumes = []
    xml_doc.search('volumeSet/item').each do |elem|
      volumes << parse_volume(elem)
    end
    return volumes
  end

  def attach_volume(volume_id, instance_id, device)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'AttachVolume',
      'VolumeId' => volume_id,
      'InstanceId' => instance_id,
      'Device' => device
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    res = {}
    res[:volume_id] = xml_doc.at('volumeId').text
    res[:instance_id] = xml_doc.at('instanceId').text
    res[:device] = xml_doc.at('device').text
    res[:status] = xml_doc.at('status').text
    res
  end

  def detach_volume(volume_id, instance_id = nil, device = nil, force = nil)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DetachVolume',
      'VolumeId' => volume_id,
      'InstanceId' => instance_id,
      'Device' => device,
      'Force' => force
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    res = {}
    res[:volume_id] = xml_doc.at('volumeId').text
    res[:instance_id] = xml_doc.at('instanceId').text
    res[:device] = xml_doc.at('device').text
    res[:status] = xml_doc.at('status').text
    res[:attach_time] = xml_doc.at('attachTime').text
    res
  end

  def create_snapshot(volume_id, description = nil)
    options = {
      'Action' => 'CreateSnapshot',
      'VolumeId' => volume_id,
    }
    options['Description'] = description unless description.nil?
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION, options)

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    res = {}
    res[:snapshot_id] = xml_doc.at('snapshotId').text
    res[:volume_id] = xml_doc.at('volumeId').text
    res[:status] = xml_doc.at('status').text
    res[:start_time] = xml_doc.at('startTime').text
    res[:progress] = xml_doc.at('progress').text
    res
  end

  def delete_snapshot(snapshot_id)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DeleteSnapshot',
      'SnapshotId' => snapshot_id
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def describe_snapshots(*snapshot_ids)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeSnapshots',
      },{
      'SnapshotId' => snapshot_ids
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)
    snapshots = []
    xml_doc.search('snapshotSet/item').each do |elem|
      snapshots << {
      :snapshot_id => elem.at('snapshotId').text,
      :volume_id => elem.at('volumeId').text,
      :status => elem.at('status').text,
      :start_time => elem.at('startTime').text,
      :progress =>  elem.at('progress').text,    
      :owner_id => elem.at('ownerId').text,
      :description => elem.at('description').text,
      }
    end
    return snapshots
  end

  def describe_snapshot_attribute(snapshot_id, attribute='createVolumePermission')
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DescribeSnapshotAttribute',
      'SnapshotId' => snapshot_id,
      'Attribute' => attribute,
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = parse_xml(response.body)

    result = {:id => xml_doc.at('snapshotId').text}

    if xml_doc.at('createVolumePermission')
      result[:create_volume_user] = []
      result[:create_volume_group] = []
      xml_doc.search('createVolumePermission/item').each do |lp|
        elems = lp.elements
        result[:create_volume_group] << elems.at('group').text if elems.at('group')
        result[:create_volume_user] << elems.at('userId').text if elems.at('userId')
      end
    end

    return result
  end

  def modify_snapshot_attribute(snapshot_id, attribute,
                             operation_type, attribute_values)

    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ModifySnapshotAttribute',
      'SnapshotId' => snapshot_id,
      'Attribute' => attribute,
      'OperationType' => operation_type,
      }, attribute_values)

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    return true
  end

  private

  def parse_xml(xml)
    Nokogiri::XML(xml) { |cfg| cfg.noblanks }.remove_namespaces!
  end
end
