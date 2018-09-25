coreo_aws_rule "administrative-policy-exposed-by-connected-ssh-credential" do
  action :define
  service :ec2
  link "http://kb.cloudcoreo.com/connected-threats-ssh-credentials"
  display_name "Publicly routable instance shares ssh-key with administrative instances"
  description "A publicly routable and addressable ec2 instance has the same ssh key as an instance with an administrative policy."
  category "Security"
  suggested_action "Generate distinct ssh keys per subnet or ec2 instance role."
  level "High"
  objectives ["describe_internet_gateways"]
  audit_objects ["object.internet_gateways.internet_gateway_id"]
  operators ["=~"]
  raise_when [//]
  id_map ["object.internet_gateways.internet_gateway_id"]
  meta_rule_query <<~QUERY
  {
    gateways as var(func: <%= filter['internet_gateway'] %>) @cascade {
        <%= default_predicates %>
        relates_to @filter(<%= filter['route'] %>) {
          <%= default_predicates %>
          relates_to @filter(<%= filter['route_table'] %>) {
            <%= default_predicates %>
            relates_to @filter(<%= filter['route_table_association'] %>) {
              <%= default_predicates %>
              relates_to @filter(<%= filter['subnet'] %>) {
                <%= default_predicates %>
                relates_to @filter(<%= filter['instance'] %> AND <%= filter['public_ip_address'] %>) {
                  <%= default_predicates %>
                  relates_to @filter(<%= filter['key_pair'] %>){
                    <%= default_predicates %>
                    exposed_keys as uid
                    relates_to @filter(<%= filter['instance'] %>){
                      <%= default_predicates %>
                      relates_to @filter(<%= filter['iam_instance_profile'] %>){
                        <%= default_predicates %>
                        relates_to @filter(<%= filter['role'] %>){
                          <%= default_predicates %>
                          relates_to @filter(<%= filter['policy'] %>){
                            <%= default_predicates %>
                            exposed_policies as uid
                            exposed_policy_arns as policy_arn
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        
      }
    }
    query(func: uid(gateways)) @cascade {
      <%= default_predicates %>
      relates_to @filter(<%= filter['route'] %>) {
        <%= default_predicates %>
        relates_to @filter(<%= filter['route_table'] %>) {
          <%= default_predicates %>
          relates_to @filter(<%= filter['route_table_association'] %>) {
            <%= default_predicates %>
            relates_to @filter(<%= filter['subnet'] %>) {
              <%= default_predicates %>
              relates_to @filter(<%= filter['instance'] %>) {
                <%= default_predicates %>
                relates_to @filter(uid(exposed_keys)){
                  <%= default_predicates %>
                  relates_to @filter(<%= filter['instance'] %>){
                    <%= default_predicates %>
                    relates_to @filter(<%= filter['iam_instance_profile'] %>){
                      <%= default_predicates %>
                      relates_to @filter(<%= filter['role'] %>){
                        <%= default_predicates %>
                        relates_to @filter(uid(exposed_policies) AND eq(val(exposed_policy_arns), "arn:aws:iam::aws:policy/AdministratorAccess")){
                          <%= default_predicates %>
                          policy_name policy_arn                      
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
    QUERY
    meta_rule_node_triggers ({'internet_gateway' => ['relates_to'], 'route' => [], 'route_table' => [], 'route_table_association' => [], 'instance' => [], 'iam_instance_profile' => [], 'role' => [] })
end
