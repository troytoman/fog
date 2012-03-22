require(File.expand_path(File.join(File.dirname(__FILE__), 'core')))

module Fog
  module Rackspace
    extend Fog::Provider

    module Errors
      class ServiceError < Fog::Errors::Error
        attr_reader :response_data

        def self.slurp(error)
          if error.response.body.empty?
            data = nil
            message = nil
          else
            data = MultiJson.decode(error.response.body)
            message = data['message']
          end

          new_error = super(error, message)
          new_error.instance_variable_set(:@response_data, data)
          new_error
        end
      end

      class InternalServerError < ServiceError; end
      class Conflict < ServiceError; end
      class NotFound < ServiceError; end
      class ServiceUnavailable < ServiceError; end

      class BadRequest < ServiceError
        #TODO - Need to find a bette way to print out these validation errors when they are thrown
        attr_reader :validation_errors

        def self.slurp(error)
          new_error = super(error)
          unless new_error.response_data.nil?
            new_error.instance_variable_set(:@validation_errors, new_error.response_data['validationErrors'])
          end
          new_error
        end
      end
    end

    service(:cdn,             'rackspace/cdn',            'CDN')
    service(:compute,         'rackspace/compute',        'Compute')
    service(:dns,             'rackspace/dns',            'DNS')
    service(:storage,         'rackspace/storage',        'Storage')
    service(:load_balancers,  'rackspace/load_balancers', 'LoadBalancers')

    def self.authenticate(options, connection_options = {})
      rackspace_auth_url = options[:rackspace_auth_url] || "auth.api.rackspacecloud.com"
      url = rackspace_auth_url.match(/^https?:/) ? \
                rackspace_auth_url : 'https://' + rackspace_auth_url
      uri = URI.parse(url)
      connection = Fog::Connection.new(url, false, connection_options)
      @rackspace_api_key  = options[:rackspace_api_key]
      @rackspace_username = options[:rackspace_username]
      response = connection.request({
        :expects  => [200, 204],
        :headers  => {
          'X-Auth-Key'  => @rackspace_api_key,
          'X-Auth-User' => @rackspace_username
        },
        :host     => uri.host,
        :method   => 'GET',
        :path     =>  (uri.path and not uri.path.empty?) ? uri.path : 'v1.0'
      })
      response.headers.reject do |key, value|
        !['X-Server-Management-Url', 'X-Storage-Url', 'X-CDN-Management-Url', 'X-Auth-Token'].include?(key)
      end
    end

    # CGI.escape, but without special treatment on spaces
    def self.escape(str,extra_exclude_chars = '')
      str.gsub(/([^a-zA-Z0-9_.-#{extra_exclude_chars}]+)/) do
        '%' + $1.unpack('H2' * $1.bytesize).join('%').upcase
      end
    end
    
    # keystone style auth
    def self.authenticate_v2(options, connection_options = {})
       rackspace_auth_url = options[:rackspace_auth_url] || "https://identity.rackspace.com/v2.0"
       uri = URI.parse(rackspace_auth_url)
       connection = Fog::Connection.new(rackspace_auth_url, false, connection_options)
       @rackspace_api_key  = options[:rackspace_api_key]
       @rackspace_username = options[:rackspace_username]
       @rackspace_tenant = options[:rackspace_tenant]
       @rackspace_region = options[:rackspace_region]
       @rackspace_compute_service_name = options[:rackspace_compute_service_name]

       req_body= {
         'auth' => {
           'RAX-KSKEY:apiKeyCredentials'  => {
             'username' => @rackspace_username,
             'apiKey' => @rackspace_api_key
           }
         }
       }
       req_body['auth']['tenantName'] = @rackspace_tenant if @rackspace_tenant

       response = connection.request({
         :expects  => [200, 204],
         :headers => {'Content-Type' => 'application/json'},
         :body  => MultiJson.encode(req_body),
         :host     => uri.host,
         :method   => 'POST',
         :path     =>  (uri.path and not uri.path.empty?) ? uri.path+"/tokens" : '/v2.0/tokens'
       })
       body=MultiJson.decode(response.body)
       
       puts body.inspect
     
       if svc = body['access']['serviceCatalog'].detect{|x| x['name'] == @rackspace_compute_service_name}
         mgmt_url = svc['endpoints'].detect{|x| x['publicURL']}['publicURL']
         token = body['access']['token']['id']
         return {
           :token => token,
           :server_management_url => mgmt_url
         } 
       else
         raise "Unable to parse service catalog."
       end
 
     end
    
  end
end
