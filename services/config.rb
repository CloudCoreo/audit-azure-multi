# TODO: rules that are service=user should not require objectives,audit_objects,operators,raise_when,id_map


coreo_uni_util_jsrunner "cloudtrail-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudtrail-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudtrail-rollup" do
  action :nothing
end

# cloudtrail end
coreo_uni_util_jsrunner "ec2-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-ec2-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-ec2-rollup" do
  action :nothing
end

# ec2 end
coreo_uni_util_jsrunner "elb-tags-rollup" do
  action :nothing
end
coreo_uni_util_notify "advise-elb-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-elb-rollup" do
  action :nothing
end

# elb end
coreo_uni_util_jsrunner "tags-rollup-iam" do
  action :nothing
end
coreo_uni_util_notify "advise-iam-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-iam-rollup" do
  action :nothing
end

#  iam end

coreo_uni_util_jsrunner "tags-rollup-rds" do
  action :nothing
end
coreo_uni_util_notify "advise-rds-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-rds-rollup" do
  action :nothing
end

# rds end
coreo_uni_util_jsrunner "tags-rollup-redshift" do
  action :nothing
end
coreo_uni_util_notify "advise-redshift-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-redshift-rollup" do
  action :nothing
end

# redshift end
coreo_uni_util_notify "advise-s3-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-s3" do
  action :nothing
end
coreo_uni_util_notify "advise-s3-rollup" do
  action :nothing
end

# s3 end

coreo_uni_util_notify "advise-cloudwatch-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-cloudwatch" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudwatch-rollup" do
  action :nothing
end

# cloudwatch end

coreo_uni_util_jsrunner "tags-rollup-cloudwatchlogs" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudwatchlogs-to-tag-values" do
  action :nothing
end
coreo_uni_util_notify "advise-cloudwatchlogs-rollup" do
  action :nothing
end

# cloudwatchlogs end

coreo_uni_util_notify "advise-kms-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-kms" do
  action :nothing
end
coreo_uni_util_notify "advise-kms-rollup" do
  action :nothing
end

# kms end

coreo_uni_util_notify "advise-sns-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-sns" do
  action :nothing
end
coreo_uni_util_notify "advise-sns-rollup" do
  action :nothing
end

# sns end

coreo_uni_util_notify "advise-config-to-tag-values" do
  action :nothing
end
coreo_uni_util_jsrunner "tags-rollup-config" do
  action :nothing
end
coreo_uni_util_notify "advise-config-rollup" do
  action :nothing
end

# config end

coreo_aws_rule "monitor-unauthorized-api-calls" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-unauthorized-api-calls.html"
  display_name "Ensure unauthorized API calls have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Unauthorized API calls are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.1"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.14.6, 3.14.7, 3.1.7, 3.4.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.errorCode = \\\"*UnauthorizedOperation\\\") || ($.errorCode = \\\"AccessDenied*\\\") }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-console-login-without-mfa" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-console-login-without-mfa.html"
  display_name "Ensure console login without MFA has monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Console logins without MFA are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.2"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7, 3.5.3"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = \\\"ConsoleLogin\\\") && ($.additionalEventData.MFAUsed != \\\"Yes\\\") }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-root-account-usage" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-root-account-usage.html"
  display_name "Ensure root account login has monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Root account logins are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ $.userIdentity.type = \\\"Root\\\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \\\"AwsServiceEvent\\\" }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-iam-policy-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-iam-policy-changes.html"
  display_name "Ensure IAM policy changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "IAM policy changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.4"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-cloudtrail-config-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cloudtrail-config-changes.html"
  display_name "Ensure CloudTrail configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "CloudTrail configuration changes are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.5"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.3.4, 3.4.3, 3.14.6, 3.14.7, 3.3.4"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-console-auth-failures" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-console-auth-failures.html"
  display_name "Ensure console authentication failures have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Console authentication failures are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.6"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7, 3.1.12"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = ConsoleLogin) && ($.errorMessage = \\\"Failed authentication\\\") }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-cmk-change-delete" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cmk-change-delete.html"
  display_name "Ensure disabled or scheduled deletion of Customer Master Keys (CMKs) have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Disabled and/or scheduled deletion of CMKs are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.7"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-s3-bucket-policy-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-s3-bucket-policy-changes.html"
  display_name "Ensure S3 bucket policy changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "S3 bucket policy changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.8"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-cloudwatch-config-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-cloudwatch-config-changes.html"
  display_name "Ensure CloudWatch configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "CloudWatch configuration changes are not properly monitored and alerted"
  level "Low"
  meta_cis_id "3.9"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.3.4, 3.4.3, 3.14.6, 3.14.7, 3.3.4"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.even tName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder)) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-security-group-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-security-group-changes.html"
  display_name "Ensure Security Groups configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Security Groups configuration changes are not properly monitored and alerted"
  level "Medium"
  meta_cis_id "3.10"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-nacl-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-nacl-changes.html"
  display_name "Ensure Network Access Control Lists (NACL) configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Network Access Control Lists (NACL) configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.11"
  meta_cis_scored "true"
  meta_cis_level "2"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-network-gateway-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-network-gateway-changes.html"
  display_name "Ensure Network Gateway configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Network Gateway configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.12"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-route-table-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-route-table-changes.html"
  display_name "Ensure Route Table configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "Route Table configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.13"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "monitor-vpc-changes" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_monitor-vpc-changes.html"
  display_name "Ensure VPC configuration changes have monitoring and alerting"
  suggested_action "Setup the metric filter, alarm, SNS topic, and subscription"
  description "VPC configuration changes are not properly monitored and alerted"
  level "High"
  meta_cis_id "3.14"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.4.3, 3.14.6, 3.14.7"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    t as var(func: <%= filter['trail'] %>) { }
    cwl as var(func: <%= filter['cloud_watch_logs_log_group'] %>) { }
    lg as var(func: <%= filter['log_group'] %>) { }
    mf as var(func: <%= filter['metric_filter'] %>) @cascade {
      fp as filter_pattern
    }
    mt as var(func: <%= filter['metric_transformation'] %>) { }
    m as var(func: <%= filter['metric'] %>) { }
    ma as var(func: <%= filter['metric_alarm'] %>) { }
    aa as var(func: <%= filter['alarm_action'] %>) { }
    st as var(func: <%= filter['sns_topic'] %>) { }
    <% range = (1..9).to_a.reverse %>
    <% range.each do |i| %>
    <% limitter = 0 %>
    query_<%= i %>(func: uid(t)) @cascade {
      <%= default_predicates %>
      <% if (limitter += 1) < i %>
      relates_to @filter(uid(cwl)) {
        <%= default_predicates %>
        <% if (limitter += 1) < i %>
        relates_to @filter(uid(lg)) {
          <%= default_predicates %>
          <% if (limitter += 1) < i %>
          relates_to @filter(uid(mf) AND eq(val(fp),"{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }")) {
            <%= default_predicates %>
            filter_pattern
            <% if (limitter += 1) < i %>
            relates_to @filter(uid(mt)) {
              <%= default_predicates %>
              <% if (limitter += 1) < i %>
              relates_to @filter(uid(m)) {
                <%= default_predicates %>
                <% if (limitter += 1) < i %>
                relates_to @filter(uid(ma)) {
                  <%= default_predicates %>
                  <% if (limitter += 1) < i %>
                  relates_to @filter(uid(aa)) {
                    <%= default_predicates %>
                    <% if (limitter += 1) < i %>
                    relates_to @filter(uid(st)) {
                      <%= default_predicates %>
                    }
                    <% end %>
                  }
                  <% end %>
                }
                <% end %>
              }
              <% end %>
            }
            <% end %>
          }
          <% end %>
        }
        <% end %>
      }
      <% end %>
    }
    <% end %>
  }
  QUERY
  meta_rule_node_triggers ({
      'trail' => [],
      'cloud_watch_logs_log_group' => [],
      'log_group' => [],
      'metric_transformation' => [],
      'sns_topic' => [],
      'metric' => [],
      'metric_filter' => ['pattern_filter'],
      'metric_alarm' => [],
      'alarm_action' => []
  })
end

coreo_aws_rule "bucket-acl-inventory" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Bucket ACL for CloudTrail trail"
  description "This is an internally defined alert"
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives    ["bucket_acl"]
  audit_objects ["object.grants.grantee.uri"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "modifiers.bucket"
end

coreo_aws_rule "bucket-logging-inventory" do
  action :define
  service :s3
  link "http://kb.cloudcoreo.com/mydoc_all-inventory.html"
  include_violations_in_count false
  display_name "Bucket Logging for CloudTrail trail"
  description "This is an internally defined alert"
  category "Internal"
  suggested_action "Ignore"
  level "Internal"
  objectives    ["bucket_logging"]
  audit_objects ["object.logging_enabled.target_bucket"]
  operators     ["=~"]
  raise_when    [//]
  id_map        "modifiers.bucket"
end

coreo_aws_rule_runner "advise-sns" do
  action :run
  rules ${AUDIT_AWS_CIS3_RULE_LIST}.reject(&:empty?).empty? ? ${AUDIT_AWS_SNS_ALERT_LIST} : ${AUDIT_AWS_SNS_ALERT_LIST}.push("sns-subscriptions-inventory-internal").uniq.reject(&:empty?)
  service :sns
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-cloudwatchlogs" do
  action :run
  rules ${AUDIT_AWS_CIS3_RULE_LIST}.reject(&:empty?).empty? ? ${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST} : ${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST}.push("cloudwatchlogs-inventory").push("cloudwatchlogsmetricfilters-inventory").uniq.reject(&:empty?)
  service :cloudwatchlogs
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "advise-cloudwatch" do
  action :run
  rules ${AUDIT_AWS_CIS3_RULE_LIST}.reject(&:empty?).empty? ? ${AUDIT_AWS_CLOUDWATCH_ALERT_LIST} : ${AUDIT_AWS_CLOUDWATCH_ALERT_LIST}.push("cloudwatch-inventory").uniq.reject(&:empty?)
  service :cloudwatch
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "cis3-rules" do
  action :run
  service :cloudtrail
  rules(${AUDIT_AWS_CIS3_RULE_LIST})
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "cloudtrail-inventory-only" do
  action :run
  service :cloudtrail
  rules(["cloudtrail-inventory-1"])
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_jsrunner "cis3-rollup" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.advise-cloudwatchlogs.report, COMPOSITE::coreo_aws_rule_runner.advise-cloudwatch.report, COMPOSITE::coreo_aws_rule_runner.advise-sns.report, COMPOSITE::coreo_aws_rule_runner.cloudtrail-inventory-runner.report]'
  function <<-'EOH'
function cloudtrailLogsLogGroupArns(region, report) {
    const logGroupArns = [];
    if (!report[region]) return logGroupArns;
    const objectIdKeys = Object.keys(report[region]);
    objectIdKeys.forEach(objectIdKey => {
        jsonBuilder(report, region, objectIdKey, 'violations', 'cloudtrail-inventory-1');
        const results = report[region][objectIdKey]['violations']['cloudtrail-inventory-1']['result_info'];
        results.forEach(result => {
            if (result['object']['cloud_watch_logs_log_group_arn']) {
                logGroupArns.push(result['object']['cloud_watch_logs_log_group_arn']);
            }
        })
    })
    return logGroupArns;
}

function jsonBuilder(a, b, c, d, e) {
  if(!a[b]) {
    a[b] = {};
  }

  if (!a[b][c])
  {
    a[b][c] = {};
  }

  if (!a[b][c][d])
  {
    a[b][c][d] = {};
  }

  if (!a[b][c][d][e])
  {
    a[b][c][d][e] = {};
  }
}

function metricsForLogGroups(region, metricFilterPattern, trailArns, logs, logsmetricfilters) {
    const metrics = [];
    if (!logs[region]) return metrics;
    const objectIdKeys = Object.keys(logs[region]);
    trailArns.forEach(trailArn => {
        objectIdKeys.forEach(objectIdKey => {
            jsonBuilder(logs, region, objectIdKey, 'violations', 'cloudwatchlogs-inventory');
             Object.keys(logsmetricfilters).forEach(region => {
                Object.keys(logsmetricfilters[region]).forEach(objectIdKey => {
                    var results = logsmetricfilters[region][objectIdKey]['violations']['cloudwatchlogsmetricfilters-inventory']['result_info'];
                    results.forEach(result => {
                        const filterPattern = result['object']['filter_pattern'].replace(/ /g, '').replace(/\\"/g, '"');
                        if (trailArn.includes(result['object']['log_group_name']) && filterPattern === metricFilterPattern) {
                            result['object']['metric_transformations'].forEach(metric => {
                                // metrics.push({ metric_name: metric['metric_name'], log_group_name: result['object']['log_group_name']});
                                metrics.push(metric['metric_name']);
                            })
                        }
                    })
                });
            });
        });
    });
    return metrics;
}

function alarmActionsForMetricFilter(region, metricFilters, cloudwatch) {
    const alarms = [];
    if (!cloudwatch[region]) return alarms;
    const objectIdKeys = Object.keys(cloudwatch[region]);
    objectIdKeys.forEach(objectIdKey => {
        jsonBuilder(cloudwatch, region, objectIdKey, 'violations', 'cloudwatch-inventory')
        const results = cloudwatch[region][objectIdKey]['violations']['cloudwatch-inventory']['result_info'];
        results.forEach(result => {
            const metricName = result['object']['metric_name'];
            if (metricFilters.includes(metricName)) {
                alarms.push(result['object']['alarm_actions']); // result['object']['alarm_actions'] is array
            }
        })
    })
    // Flatten array of arrays
    return alarms.reduce((r, i) => r.concat(i), []);
}

function subscribersToTopics(region, alarms, sns) {
    const metricSubscribers = {}; // { rule: [SNS subscriber] }
    Object.keys(alarms).forEach((rule) => metricSubscribers[rule] = []);
    if (!sns[region]) return metricSubscribers;
    const snsTopics = Object.keys(sns[region]);
    snsTopics.forEach(snsTopic => {
        const rules = Object.keys(alarms);
        if(rules) {
          rules.forEach(rule => {
              const alarmsForRule = alarms[rule];
              const alarmsMatch = alarmsForRule.filter((alarm) => snsTopic.includes(alarm));
              if (alarmsMatch.length > 0) {
                  jsonBuilder(sns, region, snsTopic, 'violations', 'sns-subscriptions-inventory-internal');
                  const results = sns[region][snsTopic]['violations']['sns-subscriptions-inventory-internal']['result_info'];
                  if (results) {
                    results.forEach(result => {
                        const subscriberEndpoint = result['object']['endpoint'];
                        metricSubscribers[rule].push(subscriberEndpoint);
                    })
                  }
              }
          })
        }
    })
    return metricSubscribers;
}

function copyViolationInNewJsonInput(regions) {
    const output = {};
    output['number_ignored_violations'] = 0;
    output['number_violations'] = 0;
    output['number_checks'] = 0;
    output['violations'] = {};
    regions.forEach(regionKey => {
        output['violations'][regionKey] = {};
        output['violations'][regionKey][regionKey] = {};
        output['violations'][regionKey][regionKey]['violations'] = {};
        output['violations'][regionKey][regionKey]['tags'] = [];
    });
    return output;
}

function updateOutputWithResults(region, results) {
    const rules = Object.keys(results);
    rules.forEach(rule => {
        // TODO: consider value of include_violations_in_count
        json_output['number_checks'] += 1;
        const ruleIsGlobal = Object.keys(globalRulesPassCounters).includes(rule);
        if (results[rule].length > 0) {
            if (ruleIsGlobal) globalRulesPassCounters[rule] += 1;
        } else if (!ruleIsGlobal) {
            json_output['violations'][region][region]['violations'][rule] = Object.assign(ruleMeta[rule]);
            json_output['violations'][region][region]['violations'][rule]['region'] = region;
            json_output['number_violations'] += 1;
        }
    })
}

function updateOutputWithGlobalResults() {
    Object.keys(globalRulesPassCounters).forEach(globalRule => {
        if (rulesArray.includes(globalRule) && globalRulesPassCounters[globalRule] === 0) {
            // We didn't pass
            const region = regionArray[0]; // Arbitrarily take first region
            json_output['violations'][region][region]['violations'][globalRule] = Object.assign(ruleMeta[globalRule]);
            json_output['violations'][region][region]['violations'][globalRule]['region'] = region;
            json_output['number_violations'] += 1;
        }
    })
}

const rulesArrayJSON = "${AUDIT_AWS_CIS3_RULE_LIST}";
const regionArrayJSON = "${AUDIT_AWS_REGIONS}";
const rulesArray = JSON.parse(rulesArrayJSON.replace(/'/g, '"'));
const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'));

const ruleMetaJSON = {
    'monitor-unauthorized-api-calls': COMPOSITE::coreo_aws_rule.monitor-unauthorized-api-calls.inputs,
    'monitor-console-login-without-mfa': COMPOSITE::coreo_aws_rule.monitor-console-login-without-mfa.inputs,
    'monitor-root-account-usage': COMPOSITE::coreo_aws_rule.monitor-root-account-usage.inputs,
    'monitor-iam-policy-changes': COMPOSITE::coreo_aws_rule.monitor-iam-policy-changes.inputs,
    'monitor-cloudtrail-config-changes': COMPOSITE::coreo_aws_rule.monitor-cloudtrail-config-changes.inputs,
    'monitor-console-auth-failures': COMPOSITE::coreo_aws_rule.monitor-console-auth-failures.inputs,
    'monitor-cmk-change-delete': COMPOSITE::coreo_aws_rule.monitor-cmk-change-delete.inputs,
    'monitor-s3-bucket-policy-changes': COMPOSITE::coreo_aws_rule.monitor-s3-bucket-policy-changes.inputs,
    'monitor-cloudwatch-config-changes': COMPOSITE::coreo_aws_rule.monitor-cloudwatch-config-changes.inputs,
    'monitor-security-group-changes': COMPOSITE::coreo_aws_rule.monitor-security-group-changes.inputs,
    'monitor-nacl-changes': COMPOSITE::coreo_aws_rule.monitor-nacl-changes.inputs,
    'monitor-network-gateway-changes': COMPOSITE::coreo_aws_rule.monitor-network-gateway-changes.inputs,
    'monitor-route-table-changes': COMPOSITE::coreo_aws_rule.monitor-route-table-changes.inputs,
    'monitor-vpc-changes': COMPOSITE::coreo_aws_rule.monitor-vpc-changes.inputs
};
const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
const ruleMeta = {};
Object.keys(ruleMetaJSON).forEach(rule => {
    const flattenedRule = {};
    ruleMetaJSON[rule].forEach(input => {
        if (ruleInputsToKeep.includes(input.name)) flattenedRule[input.name] = input.value;
    })
    flattenedRule["service"] = "multi";
    ruleMeta[rule] = flattenedRule;
})

// 3.2, 3.3, 3.4, 3.6, 3.8 are violations for global services IAM or S3
const globalRulesPassCounters = {
    'monitor-console-login-without-mfa': 0,
    'monitor-root-account-usage': 0,
    'monitor-iam-policy-changes': 0,
    'monitor-console-auth-failures': 0,
    'monitor-s3-bucket-policy-changes': 0
}

const cloudwatchlogsmetricfilters = {};
const cloudwatchlogs = {};
Object.keys(json_input[0]).forEach(region => {
    Object.keys(json_input[0][region]).forEach(obj => {
        if(json_input[0][region][obj]['violator_info'].hasOwnProperty('arn')) {
            if(!(cloudwatchlogs.hasOwnProperty(region))) { cloudwatchlogs[region] = {}; }
            cloudwatchlogs[region][obj] = json_input[0][region][obj];
        } else if(json_input[0][region][obj]['violator_info'].hasOwnProperty('filter_pattern')) {
            if(!(cloudwatchlogsmetricfilters.hasOwnProperty(region))) { cloudwatchlogsmetricfilters[region] = {}; }
            cloudwatchlogsmetricfilters[region][obj] = json_input[0][region][obj];
        }
    });
});

const cloudwatch = json_input[1];
const sns = json_input[2];
const cloudtrail = json_input[3];

const metricFilterPatterns = {
    'monitor-unauthorized-api-calls': '{($.errorCode = "*UnauthorizedOperation") || ($.errorCode ="AccessDenied*") }', // 3.1
    'monitor-console-login-without-mfa': '{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") }', // 3.2
    'monitor-root-account-usage': '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != "AwsServiceEvent" }', // 3.3
    'monitor-iam-policy-changes': '{($.eventName=DeleteGroupPolicy)||($.eventName=DeleteRolePolicy)||($.eventName=DeleteUserPolicy)||($.eventName=PutGroupPolicy)||($.eventName=PutRolePolicy)||($.eventName=PutUserPolicy)||($.eventName=CreatePolicy)||($.eventName=DeletePolicy)||($.eventName=CreatePolicyVersion)||($.eventName=DeletePolicyVersion)||($.eventName=AttachRolePolicy)||($.eventName=DetachRolePolicy)||($.eventName=AttachUserPolicy)||($.eventName=DetachUserPolicy)||($.eventName=AttachGroupPolicy)||($.eventName=DetachGroupPolicy)}', // 3.4
    'monitor-cloudtrail-config-changes': '{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }', // 3.5
    'monitor-console-auth-failures': '{ ($.eventName = ConsoleLogin) && ($.errorMessage = "Failed authentication") }', // 3.6
    'monitor-cmk-change-delete': '{($.eventSource = kms.amazonaws.com) && (($.eventName=DisableKey)||($.eventName=ScheduleKeyDeletion))}', // 3.7
    'monitor-s3-bucket-policy-changes': '{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }', // 3.8
    'monitor-cloudwatch-config-changes': '{($.eventSource = config.amazonaws.com) && (($.eventName=StopConfigurationRecorder)||($.eventName=DeleteDeliveryChannel)||($.even tName=PutDeliveryChannel)||($.eventName=PutConfigurationRecorder))}', // 3.9
    'monitor-security-group-changes': '{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup)}', // 3.10
    'monitor-nacl-changes': '{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }', // 3.11
    'monitor-network-gateway-changes': '{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }', // 3.12
    'monitor-route-table-changes': '{ ($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable) }', // 3.13
    'monitor-vpc-changes': '{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }' // 3.14
};
Object.keys(metricFilterPatterns).forEach((m) => metricFilterPatterns[m] = metricFilterPatterns[m].replace(/ /g, ''));

const json_output = copyViolationInNewJsonInput(regionArray);

regionArray.forEach(region => {
    const cloudtrailArns = cloudtrailLogsLogGroupArns(region, cloudtrail);
    const snsAlarms = {}; // { rule: [alarmsArray], ... }

    rulesArray.forEach(rule => {
        const metricFilter = metricFilterPatterns[rule]
        if (!metricFilter) {
            console.log(`unknown rule: ${rule}`);
            return;
        }
        const metricsForUnauthApiCalls = metricsForLogGroups(region, metricFilter, cloudtrailArns, cloudwatchlogs, cloudwatchlogsmetricfilters);
        snsAlarms[rule] = alarmActionsForMetricFilter(region, metricsForUnauthApiCalls, cloudwatch);
    })

    const metricSubscribers = subscribersToTopics(region, snsAlarms, sns);
    updateOutputWithResults(region, metricSubscribers);
})

updateOutputWithGlobalResults();

coreoExport('number_ignored_violations', json_output['number_ignored_violations']);
coreoExport('number_violations', json_output['number_violations']);
coreoExport('number_checks', json_output['number_checks']);

callback(json_output['violations']);
EOH
end

coreo_uni_util_variables "rollup-update-advisor-output" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.cis3-rules.number_ignored_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.cis3-rollup.number_ignored_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.cis3-rules.number_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.cis3-rollup.number_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.cis3-rules.number_checks' => 'COMPOSITE::coreo_uni_util_jsrunner.cis3-rollup.number_checks'},
                {'COMPOSITE::coreo_aws_rule_runner.cis3-rules.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis3-rollup.return'}
            ])
end

coreo_aws_rule "s3-cloudtrail-public-access" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_s3-cloudtrail-public-access.html"
  display_name "Ensure S3 bucket for CloudTrail logs not publicly accessible"
  suggested_action "Remove any public access that has been granted to CloudTrail buckets"
  description "Access controls (ACLs) to CloudTrail S3 logging buckets allow public access"
  level "High"
  meta_cis_id "2.3"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.3.1"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    tr as var(func: <%= filter['trail'] %>) @cascade{
      b as relates_to @filter(<%= filter['bucket'] %>) {
        ba as relates_to @filter(<%= filter['bucket_acl'] %>) {
          bag as relates_to @filter(<%= filter['bucket_acl_grant'] %>) {
            g as relates_to @filter(<%= filter['grantee'] %>) {
              u as uri
            }
          }
        }
      }
    }
  
    query(func: uid(tr)) @cascade {
      <%= default_predicates %>
      relates_to @filter(uid(b)) {
        <%= default_predicates %>
        relates_to @filter(uid(ba)) {
          <%= default_predicates %>
          relates_to @filter(uid(bag)) {
            <%= default_predicates %>
            relates_to @filter(uid(g) AND (eq(val(u),"http://acs.amazonaws.com/groups/global/AllUsers") OR  eq(val(u),"http://acs.amazonaws.com/groups/global/AuthenticatedUsers"))) {
              <%= default_predicates %>
              uri
            }
          }
        }
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'trail' => [],
                              'bucket' => [],
                              'bucket_acl' => [],
                              'bucket_acl_grant' => [],
                              'grantee' => ['uri']
                          })
end

coreo_aws_rule "s3-cloudtrail-no-logging" do
  action :define
  service :user
  category "Audit"
  link "http://kb.cloudcoreo.com/mydoc_s3-cloudtrail-no-logging.html"
  display_name "Ensure S3 bucket logging is enabled for CloudTrail logs"
  suggested_action "S3 Bucket access logging be enabled on the CloudTrail S3 bucket"
  description "Logging of CloudTrail S3 bucket is not configured"
  level "Medium"
  meta_cis_id "2.6"
  meta_cis_scored "true"
  meta_cis_level "1"
  meta_nist_171_id "3.3.2"
  objectives [""]
  audit_objects [""]
  operators [""]
  raise_when [true]
  id_map "static.no_op"
  meta_rule_query <<~QUERY
  {
    twb as var(func: <%= filter['trail'] %>) @cascade {
      relates_to @filter(<%= filter['bucket'] %>) {
        relates_to @filter(<%= filter['bucket_logging'] %>) {
        }
      }
    }
  
    query(func: has(trail)) @filter(NOT uid(twb)) {
      <%= default_predicates %>
      relates_to @filter(has(bucket)) {
        <%= default_predicates %>
      }
    }
  }
  QUERY
  meta_rule_node_triggers({
                              'trail' => [],
                              'bucket' => [],
                              'bucket_logging' => []
                          })
end

coreo_aws_rule_runner "cis2-rules" do
  action :run
  service :cloudtrail
  rules(${AUDIT_AWS_CIS2_RULE_LIST})
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_aws_rule_runner "bucket-inventory" do
  service :s3
  action :run
  rules ${AUDIT_AWS_CIS2_RULE_LIST}.reject(&:empty?).empty? ? [""] : ["bucket-logging-inventory", "bucket-acl-inventory"]
  global_objective "buckets"
  global_modifier({:bucket => "buckets.name"})
  regions ${AUDIT_AWS_REGIONS}
  filter(${FILTERED_OBJECTS}) if ${FILTERED_OBJECTS}
end

coreo_uni_util_jsrunner "cis26-cis23-processor" do
  action :run
  json_input '[COMPOSITE::coreo_aws_rule_runner.bucket-inventory.report, COMPOSITE::coreo_aws_rule_runner.cloudtrail-inventory-only.report]'
  function <<-'EOH'
function copyViolationInNewJsonInput(regions) {
    const output = {};
    output['number_ignored_violations'] = 0;
    output['number_violations'] = 0;
    output['number_checks'] = 0;
    output['violations'] = {};
    regions.forEach(regionKey => {
        output['violations'][regionKey] = {};
    });
    return output;
}

function updateOutputWithResults(region, bucket, result, targetRule, sourceRule) {
    json_output['number_violations'] = json_output['number_violations'] + 1;

    if (!json_output['violations'][region][bucket]) {
        json_output['violations'][region][bucket] = {};
        json_output['violations'][region][bucket]['violator_info'] = result['violator_info'];
    }
    if (!json_output['violations'][region][bucket]['violations']) {
        json_output['violations'][region][bucket]['violations'] = {};
    }
    if (!json_output['violations'][region][bucket]['tags']) {
        json_output['violations'][region][bucket]['tags'] = result['tags'];
    }

    json_output['violations'][region][bucket]['violations'][targetRule] = Object.assign(ruleMeta[targetRule]);
    json_output['violations'][region][bucket]['violations'][targetRule]['region'] = region;

    if (result['violations'][sourceRule]) {
        // Overwrite region if defined in violation because of S3 bucket locations
        json_output['violations'][region][bucket]['violations'][targetRule]['region'] = result['violations'][sourceRule]['region'];
        json_output['violations'][region][bucket]['violations'][targetRule]['result_info'] = result['violations'][sourceRule]['result_info'];
    }
}

const CLOUDTRAIL_INVENTORY_RULE = 'cloudtrail-inventory-1';
const S3_ACL_INVENTORY_RULE = 'bucket-acl-inventory';
const S3_LOGGING_INVENTORY_RULE = 'bucket-logging-inventory';
const VIOLATING_GRANTEE_URIS = [
    'http://acs.amazonaws.com/groups/global/AllUsers',
    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
];

const ruleMetaJSON = {
    's3-cloudtrail-public-access': COMPOSITE::coreo_aws_rule.s3-cloudtrail-public-access.inputs,
    's3-cloudtrail-no-logging': COMPOSITE::coreo_aws_rule.s3-cloudtrail-no-logging.inputs
};
const ruleInputsToKeep = ['service', 'category', 'link', 'display_name', 'suggested_action', 'description', 'level', 'meta_cis_id', 'meta_cis_scored', 'meta_cis_level', 'include_violations_in_count'];
const ruleMeta = {};
Object.keys(ruleMetaJSON).forEach(rule => {
    const flattenedRule = {};
    ruleMetaJSON[rule].forEach(input => {
        if (ruleInputsToKeep.includes(input.name)) flattenedRule[input.name] = input.value;
    })
    ruleMeta[rule] = flattenedRule;
})

const rulesArrayJSON = "${AUDIT_AWS_CIS2_RULE_LIST}";
const regionArrayJSON = "${AUDIT_AWS_REGIONS}";
const rulesArray = JSON.parse(rulesArrayJSON.replace(/'/g, '"'));
const regionArray = JSON.parse(regionArrayJSON.replace(/'/g, '"'));

const s3BucketInventory = json_input[0];
const cloudtrail = json_input[1];

const json_output = copyViolationInNewJsonInput(regionArray);

const trailsToCheck = [];
regionArray.forEach(region => {
    // There can be no violations without trails
    if (!cloudtrail[region]) return;

    const trails = Object.keys(cloudtrail[region]);
    trails.forEach(trail => {
        const results = cloudtrail[region][trail]['violations'][CLOUDTRAIL_INVENTORY_RULE]['result_info'];
        results.forEach(result => {
            const bucket = result['object']['s3_bucket_name'];
            if (bucket) {
                trailsToCheck.push(bucket);
            }
        })
    })
})

regionArray.forEach(region => {
    if (!s3BucketInventory[region]) return;
    const buckets = Object.keys(s3BucketInventory[region]);
    buckets.forEach(bucket => {
        if (trailsToCheck.includes(bucket)) {
            let targetRule = 's3-cloudtrail-public-access';
            if (rulesArray.includes(targetRule)) {
                let haveACLViolation = false;
                if (s3BucketInventory[region][bucket]['violations'][S3_ACL_INVENTORY_RULE]) {
                    const bucketACLResults = s3BucketInventory[region][bucket]['violations'][S3_ACL_INVENTORY_RULE]['result_info'];
                    bucketACLResults.forEach(result => {
                        json_output['number_checks'] = json_output['number_checks'] + 1;
                        const granteeURI = result['object']['uri'];
                        if (VIOLATING_GRANTEE_URIS.includes(granteeURI)) {
                            haveACLViolation = true;
                        }
                    })
                    if (haveACLViolation) {
                        const sourceRule = S3_ACL_INVENTORY_RULE;
                        updateOutputWithResults(region, bucket, s3BucketInventory[region][bucket], targetRule, sourceRule);
                    }
                }
            }

            targetRule = 's3-cloudtrail-no-logging';
            if (rulesArray.includes(targetRule)) {
                let haveLoggingViolation = false;
                if (s3BucketInventory[region][bucket]['violations'][S3_LOGGING_INVENTORY_RULE]) {
                    const bucketLoggingResults = s3BucketInventory[region][bucket]['violations'][S3_LOGGING_INVENTORY_RULE]['result_info'];
                    bucketLoggingResults.forEach(result => {
                        json_output['number_checks'] = json_output['number_checks'] + 1;
                        const targetBucket = result['object']['target_bucket'];
                        if (!targetBucket) {
                            haveLoggingViolation = true;
                        }
                    })
                } else {
                    haveLoggingViolation = true;
                    json_output['number_checks'] = json_output['number_checks'] + 1;
                }
                if (haveLoggingViolation) {
                    const sourceRule = S3_LOGGING_INVENTORY_RULE;
                    updateOutputWithResults(region, bucket, s3BucketInventory[region][bucket], targetRule, sourceRule);
                }
            }
        }
    })
})

coreoExport('number_ignored_violations', json_output['number_ignored_violations']);
coreoExport('number_violations', json_output['number_violations']);
coreoExport('number_checks', json_output['number_checks']);

callback(json_output['violations']);
EOH
end

coreo_uni_util_variables "rollup-update-advisor-output-cis2" do
  action :set
  variables([
                {'COMPOSITE::coreo_aws_rule_runner.cis2-rules.number_ignored_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.cis2-rollup.number_ignored_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.cis2-rules.number_violations' => 'COMPOSITE::coreo_uni_util_jsrunner.cis2-rollup.number_violations'},
                {'COMPOSITE::coreo_aws_rule_runner.cis2-rules.number_checks' => 'COMPOSITE::coreo_uni_util_jsrunner.cis2-rollup.number_checks'},
                {'COMPOSITE::coreo_aws_rule_runner.cis2-rules.report' => 'COMPOSITE::coreo_uni_util_jsrunner.cis26-cis23-processor.return'}
            ])
end

coreo_uni_util_variables "aws-planwide" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.composite_name' => 'PLAN::stack_name'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.plan_name' => 'PLAN::name'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'unset'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.number_violations' => '0'}
            ])
end

coreo_uni_util_jsrunner "splice-violation-object" do
  action :run
  data_type "json"
  json_input '
  {"composite name":"PLAN::stack_name","plan name":"PLAN::name", "services": {
  "cloudtrail": {
   "composite name":"PLAN::stack_name",
   "plan name":"PLAN::name",
   "audit name": "CloudTrail",
    "cloud account name":"PLAN::cloud_account_name",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-cloudtrail.report },
  "ec2": {
   "audit name": "EC2",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-ec2.report },
    "cloudwatch": {
      "audit name": "CLOUDWATCH",
      "violations": COMPOSITE::coreo_aws_rule_runner.advise-cloudwatch.report
    },
    "sns": {
      "audit name": "SNS",
      "violations": COMPOSITE::coreo_aws_rule_runner.advise-sns.report
    },
    "kms": {
      "audit name": "KMS",
      "violations": COMPOSITE::coreo_aws_rule_runner.advise-kms.report
    },
  "cloudwatchlogs": {
   "audit name": "CLOUDWATCHLOGS",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-cloudwatchlogs.report },
  "iam": {
   "audit name": "IAM",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-iam.report },
  "elb": {
   "audit name": "ELB",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-elb.report },
  "rds": {
   "audit name": "RDS",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-rds.report },
  "redshift": {
   "audit name": "REDSHIFT",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-redshift.report },
  "s3": {
   "audit name": "S3",
   "violations": COMPOSITE::coreo_aws_rule_runner.advise-s3.report }
  }}'
  function <<-EOH
  const wayToServices = json_input['services'];
  let newViolation = {};
  let violationCounter = 0;
  const auditStackKeys = Object.keys(wayToServices);
  auditStackKeys.forEach(auditStackKey => {
      let wayForViolation = wayToServices[auditStackKey]['violations'];
      const violationKeys = Object.keys(wayForViolation);
      violationKeys.forEach(violationRegion => {
          if(!newViolation.hasOwnProperty(violationRegion)) {
              newViolation[violationRegion] = {};
          }
          const ruleKeys = Object.keys(wayForViolation[violationRegion]);
          violationCounter+= ruleKeys.length;
          ruleKeys.forEach(objectKey => {
              if(!newViolation[violationRegion].hasOwnProperty(objectKey)) {
                  newViolation[violationRegion][objectKey] = {};
                  newViolation[violationRegion][objectKey]['violations'] = {};
              }
              const objectKeys = Object.keys(wayForViolation[violationRegion][objectKey]['violations']);
              objectKeys.forEach(ruleKey => {
                  newViolation[violationRegion][objectKey]['tags'] = wayForViolation[violationRegion][objectKey]['tags'];
                  newViolation[violationRegion][objectKey]['violations'][ruleKey] = wayForViolation[violationRegion][objectKey]['violations'][ruleKey];
              })
          })
      });
  });
  coreoExport('violationCounter', JSON.stringify(violationCounter));
  callback(newViolation);
  EOH
end

coreo_uni_util_variables "aws-update-planwide-1" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'COMPOSITE::coreo_aws_rule_runner.splice-violation-object.report'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.number_violations' => 'COMPOSITE::coreo_aws_rule_runner.splice-violation-object.violationCounter'},

            ])
end


coreo_uni_util_jsrunner "tags-to-notifiers-array-aws" do
  action :run
  data_type "json"
  provide_composite_access true
  packages([
               {
                   :name => "cloudcoreo-jsrunner-commons",
                   :version => "1.10.7-beta65"
               },
               {
                   :name => "js-yaml",
                   :version => "3.7.0"
               }])
  json_input '{ "compositeName":"PLAN::stack_name",
                "planName":"PLAN::name",
                "teamName":"PLAN::team_name",
                "cloudAccountName": "PLAN::cloud_account_name",
                "violations": COMPOSITE::coreo_uni_util_jsrunner.splice-violation-object.return}'
  function <<-EOH

const compositeName = json_input.compositeName;
const planName = json_input.planName;
const cloudAccount = json_input.cloudAccountName;
const cloudObjects = json_input.violations;
const teamName = json_input.teamName;

const NO_OWNER_EMAIL = "${AUDIT_AWS_ALERT_RECIPIENT}";
const OWNER_TAG = "${AUDIT_AWS_OWNER_TAG}";
const ALLOW_EMPTY = "${AUDIT_AWS_ALLOW_EMPTY}";
const SEND_ON = "${AUDIT_AWS_SEND_ON}";
const htmlReportSubject = "${HTML_REPORT_SUBJECT}";

let cloudtrailAlertListToJSON = "${AUDIT_AWS_CLOUDTRAIL_ALERT_LIST}";
let redshiftAlertListToJSON = "${AUDIT_AWS_REDSHIFT_ALERT_LIST}";
let rdsAlertListToJSON = "${AUDIT_AWS_RDS_ALERT_LIST}";
let iamAlertListToJSON = "${AUDIT_AWS_IAM_ALERT_LIST}";
let elbAlertListToJSON = "${AUDIT_AWS_ELB_ALERT_LIST}";
let ec2AlertListToJSON = "${AUDIT_AWS_EC2_ALERT_LIST}";
let s3AlertListToJSON = "${AUDIT_AWS_S3_ALERT_LIST}";
let cloudwatchAlertListToJSON = "${AUDIT_AWS_CLOUDWATCH_ALERT_LIST}";
let cloudwatchlogsAlertListToJSON = "${AUDIT_AWS_CLOUDWATCHLOGS_ALERT_LIST}";
let kmsAlertListToJSON = "${AUDIT_AWS_KMS_ALERT_LIST}";
let snsAlertListToJSON = "${AUDIT_AWS_SNS_ALERT_LIST}";


const alertListMap = new Set();

alertListMap.add(JSON.parse(cloudtrailAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(redshiftAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(rdsAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(iamAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(elbAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(ec2AlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(s3AlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(cloudwatchAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(cloudwatchlogsAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(kmsAlertListToJSON.replace(/'/g, '"')));
alertListMap.add(JSON.parse(snsAlertListToJSON.replace(/'/g, '"')));


let auditAwsAlertList = [];

alertListMap.forEach(alertList => {
    auditAwsAlertList = auditAwsAlertList.concat(alertList);
});

const alertListArray = auditAwsAlertList;
const ruleInputs = {};

let userSuppression;
let userSchemes;

const fs = require('fs');
const yaml = require('js-yaml');
function setSuppression() {
  try {
      userSuppression = yaml.safeLoad(fs.readFileSync('./suppression.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in suppression.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSuppression=[];
    }
  }

  coreoExport('suppression', JSON.stringify(userSuppression));
}

function setTable() {
  try {
    userSchemes = yaml.safeLoad(fs.readFileSync('./table.yaml', 'utf8'));
  } catch (e) {
    if (e.name==="YAMLException") {
      throw new Error("Syntax error in table.yaml file. "+ e.message);
    }
    else{
      console.log(e.name);
      console.log(e.message);
      userSchemes={};
    }
  }

  coreoExport('table', JSON.stringify(userSchemes));
}
setSuppression();
setTable();

const argForConfig = {
    NO_OWNER_EMAIL, cloudObjects, userSuppression, OWNER_TAG,
    userSchemes, alertListArray, ruleInputs, ALLOW_EMPTY,
    SEND_ON, cloudAccount, compositeName, planName, htmlReportSubject, teamName
}


function createConfig(argForConfig) {
    let JSON_INPUT = {
        compositeName: argForConfig.compositeName,
        htmlReportSubject: argForConfig.htmlReportSubject,
        planName: argForConfig.planName,
        teamName: argForConfig.teamName,
        violations: argForConfig.cloudObjects,
        userSchemes: argForConfig.userSchemes,
        userSuppression: argForConfig.userSuppression,
        alertList: argForConfig.alertListArray,
        disabled: argForConfig.ruleInputs,
        cloudAccount: argForConfig.cloudAccount
    };
    let SETTINGS = {
        NO_OWNER_EMAIL: argForConfig.NO_OWNER_EMAIL,
        OWNER_TAG: argForConfig.OWNER_TAG,
        ALLOW_EMPTY: argForConfig.ALLOW_EMPTY, SEND_ON: argForConfig.SEND_ON,
        SHOWN_NOT_SORTED_VIOLATIONS_COUNTER: false
    };
    return {JSON_INPUT, SETTINGS};
}

const {JSON_INPUT, SETTINGS} = createConfig(argForConfig);
const CloudCoreoJSRunner = require('cloudcoreo-jsrunner-commons');

const emails = CloudCoreoJSRunner.createEmails(JSON_INPUT, SETTINGS);
const suppressionJSON = CloudCoreoJSRunner.createJSONWithSuppress(JSON_INPUT, SETTINGS);

coreoExport('JSONReport', JSON.stringify(suppressionJSON));
coreoExport('report', JSON.stringify(suppressionJSON['violations']));

callback(emails);
  EOH
end


coreo_uni_util_variables "aws-update-planwide-2" do
  action :set
  variables([
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.results' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.JSONReport'},
                {'COMPOSITE::coreo_uni_util_variables.aws-planwide.table' => 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.table'}
            ])
end

coreo_uni_util_jsrunner "tags-rollup-aws" do
  action :run
  data_type "text"
  json_input 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.return'
  function <<-EOH
const notifiers = json_input;


function setTextRollup() {
    let emailText = '';
    let numberOfViolations = 0;
    let usedEmails=new Map();
    notifiers.forEach(notifier => {
        const hasEmail = notifier['endpoint']['to'].length;
        const email = notifier['endpoint']['to'];
        if(hasEmail && usedEmails.get(email)!==true) {
            usedEmails.set(email,true);
            numberOfViolations += parseInt(notifier['num_violations']);
            emailText += "recipient: " + notifier['endpoint']['to'] + " - " + "Violations: " + notifier['numberOfViolatingCloudObjects'] + ", Cloud Objects: "+ (notifier["num_violations"]-notifier['numberOfViolatingCloudObjects']) + "\\n";
        }
    });

    textRollup += 'Total Number of matching Cloud Objects: ' + numberOfViolations + "\\n";
    textRollup += 'Rollup' + "\\n";
    textRollup += emailText;

}


let textRollup = '';
setTextRollup();

callback(textRollup);
  EOH
end

coreo_uni_util_notify "advise-aws-to-tag-values" do
  action((("${AUDIT_AWS_ALERT_RECIPIENT}".length > 0)) ? :notify : :nothing)
  notifiers 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.return'
end

coreo_uni_util_notify "advise-aws-rollup" do
  action((("${AUDIT_AWS_ALERT_RECIPIENT}".length > 0) and (! "${AUDIT_AWS_OWNER_TAG}".eql?("NOT_A_TAG"))) ? :notify : :nothing)
  type 'email'
  allow_empty true
  send_on 'always'
  payload '
composite name: PLAN::stack_name
plan name: PLAN::name
COMPOSITE::coreo_uni_util_jsrunner.tags-rollup-aws.return
  '
  payload_type 'text'
  endpoint ({
      :to => '${AUDIT_AWS_ALERT_RECIPIENT}', :subject => 'CloudCoreo aws rule results on PLAN::stack_name :: PLAN::name'
  })
end

coreo_aws_s3_policy "cloudcoreo-audit-aws-multi-policy" do
  action((("${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  policy_document <<-EOF
{
"Version": "2012-10-17",
"Statement": [
{
"Sid": "",
"Effect": "Allow",
"Principal":
{ "AWS": "*" }
,
"Action": "s3:*",
"Resource": [
"arn:aws:s3:::bucket-${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}/*",
"arn:aws:s3:::bucket-${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}"
]
}
]
}
  EOF
end

coreo_aws_s3_bucket "bucket-${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}" do
  action((("${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :create : :nothing)
  bucket_policies ["cloudcoreo-audit-aws-multi-policy"]
end

coreo_uni_util_notify "cloudcoreo-audit-aws-multi-s3" do
  action((("${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}".length > 0) ) ? :notify : :nothing)
  type 's3'
  allow_empty true
  payload 'COMPOSITE::coreo_uni_util_jsrunner.tags-to-notifiers-array-aws.report'
  endpoint ({
      object_name: 'aws-multi-json',
      bucket_name: 'bucket-${AUDIT_AWS_MULTI_S3_NOTIFICATION_BUCKET_NAME}',
      folder: 'multi/PLAN::name',
      properties: {}
  })
end
