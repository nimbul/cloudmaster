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
    instance = {
      :reserved_instances_id => elem.at('reservedInstancesId').text,
      :instance_type => elem.at('instanceType').text,
      :zone => elem.at('availabilityZone').text,
      :start => elem.at('start').text,
      :duration => elem.at('duration').text,
      :fixed_price => elem.at('fixedPrice').text,
      :usage_price => elem.at('usagePrice').text,
      :count => elem.at('instanceCount').text,
      :description => elem.at('productDescription').text,
      :state => elem.at('state').text,
    }
    return instance
  end

  def parse_reservation(elem)
    reservation = {
      :reservation_id => elem.at('reservationId').text,
      :owner_id => elem.at('ownerId').text,
    }

    group_names = []
    elem.search('groupSet/item').each do |group|
      group_names << group.at('groupId').text
    end
    reservation[:groups] = group_names

    reservation[:instances] = []
    elem.search('instancesSet/item').each do |instance|
      elems = instance.elements
      item = {
        :id => elems.at('instanceId').text,
        :image_id => elems.at('imageId').text,
        :state => elems.at('instanceState/name').text,
        :private_dns => elems.at('privateDnsName').text,
        :public_dns => elems.at('dnsName').text,
      }

      item[:reason] = elems.at('reason').text if elems.at('reason')
      item[:key_name] = elems.at('keyName').text if elems.at('keyName')
      item[:index] = elems.at('amiLaunchIndex').text if elems.at('amiLaunchIndex')

      if elems.at('productCodes')
        item[:product_codes] = []
        elems.search('productCodes/item/productCode').each do |code|
          item[:product_codes] << code.text
        end
      end

      item[:type] = elems.at('instanceType').text if elems.at('instanceType')
      item[:launch_time] = elems.at('launchTime').text if elems.at('launchTime')

      if elems.at('placement')
        item[:zone] = elems.at('placement/availabilityZone').text
      end
      item[:kernel_id] = elems.at('kernelId').text if elems.at('kernelId')
      item[:ramdisk_id] = elems.at('ramdiskId').text if elems.at('ramdiskId')

      item[:platform] = elems.at('platform').text if elems.at('platform')
      item[:monitoring] = elems.at('monitoring/state').text if elems.at('monitoring/state')
      item[:subnet_id] = elems.at('subnetId').text if elems.at('subnetId')
      item[:vpc_id] = elems.at('vpcId').text if elems.at('vpcId')
      item[:private_ip] = elems.at('privateIpAddress').text if elems.at('privateIpAddress')
      item[:public_ip] = elems.at('ipAddress').text if elems.at('ipAddress')
      # sourceDestCheck
      # groupSet
      # stateReason
      item[:architecture] = elems.at('architecture').text if elems.at('architecture')
      item[:root_device_type] = elems.at('rootDeviceType').text if elems.at('rootDeviceType')
      item[:root_device_name] = elems.at('rootDeviceName').text if elems.at('rootDeviceName')

      reservation[:instances] << item
    end

    return reservation
  end

  def parse_volume(elem)
    volume = {
      :volume_id => elem.at('volumeId').text,
      :size => elem.at('size').text,
      :status => elem.at('status').text,
      :create_time => elem.at('createTime').text,
      :snapshot_id => elem.at('snapshotId').text,
      :availability_zone => elem.at('availabilityZone').text,
    }
    attachments = []
    elem.search('attachmentSet/item').each do |attachment|
      attachments << {
        :volume_id => attachment.at('volumeId').text,
        :instance_id => attachment.at('instanceId').text,
        :device => attachment.at('device').text,
        :status => attachment.at('status').text,
        :attach_time => attachment.at('attachTime').text
      }
    end
    volume[:attachment_set] = attachments
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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

    images = []
    xml_doc.search('imagesSet/item').each do |image|
      image_details = {
        :id => image.at('imageId').text,
        :location => image.at('imageLocation').text,
        :state => image.at('imageState').text,
        :owner_id => image.at('imageOwnerId').text,
        :is_public => image.at('isPublic').text == 'true',
        :architecture => image.at('architecture').text,
        :type => image.at('imageType').text,
      }

      #
      # new fields in ec2 api: name, description, rootDeviceName and rootDeviceType
      #
      if image.at('name')
        image_details[:name] = image.at('name').text
      end
      
      if image.at('description')
        image_details[:description] = image.at('description').text
      end
      
      if image.at('rootDeviceName')
        image_details[:root_device_name] = image.at('rootDeviceName').text
      end
      
      if image.at('rootDeviceType')
        image_details[:root_device_type] = image.at('rootDeviceType').text
      end

      #
      # fill out block device mapping
      #
      block_device_mapping = []
      image.search('blockDeviceMapping/item').each do |mapping|
        m = {}
        m[:device_name] = mapping.at('deviceName').text if mapping.elements.at('deviceName')
        m[:virtual_name] = mapping.at('virtualName').text if mapping.elements.at('virtualName')
        m[:no_device] = !mapping.at('noDevice').nil?
        ebs = {}
        ebs[:snapshot_id] = mapping.at('ebs/snapshotId').text if mapping.elements.at('ebs/snapshotId')
        ebs[:volume_size] = mapping.at('ebs/volumeSize').text if mapping.elements.at('ebs/volumeSize')
        ebs[:delete_on_termination] = (mapping.at('ebs/deleteOnTermination') and mapping.elements.at('ebs/deleteOnTermination').text == 'true')
        m[:ebs] = ebs
        block_device_mapping << m
      end
      image_details[:block_device_mapping] = block_device_mapping
      
      # Items only available when listing 'machine' image types
      # that have associated kernel and ramdisk metadata
      if image.at('kernelId') 
        image_details[:kernel_id] = image.at('kernelId').text
      end
      if image.at('ramdiskId')
        image_details[:ramdisk_id] = image.at('ramdiskId').text
      end
      
      image.search('productCodes/item/productCode').each do |code|
        image_details[:product_codes] ||= []
        image_details[:product_codes] << code.text
      end

      images << image_details
    end

    return images
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)

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
    elems = Nokogiri.XML(response.body).elements

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
    elems = Nokogiri.XML(response.body).elements

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
    xml_doc = Nokogiri.XML(response.body)

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
    xml_doc = Nokogiri.XML(response.body)
    return xml_doc.at('publicIp').text
  end

  def release_address(public_ip)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'ReleaseAddress',
      'PublicIp' => public_ip
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
    return xml_doc.at('return').text == 'true'
  end

  def disassociate_address(public_ip)
    parameters = build_query_params(API_VERSION, SIGNATURE_VERSION,
      {
      'Action' => 'DisassociateAddress',
      'PublicIp' => public_ip
      })

    response = do_query(HTTP_METHOD, ENDPOINT_URI, parameters)
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)
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
    xml_doc = Nokogiri.XML(response.body)

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

end
