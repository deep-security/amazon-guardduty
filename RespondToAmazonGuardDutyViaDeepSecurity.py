from __future__ import print_function

# standard library
import json
import os
import urllib2

# 3rd party dependencies
import deepsecurity

# settings
ENABLE_SLACK = False
ENABLE_MODULES = False
DSM = None

def is_event_from_guardduty(event):
  """
  Is this event from Amazon GuardDuty?
  """
  result = False

  if event.has_key('source') and event['source'].lower() == 'aws.guardduty' and event.has_key('detail') and event['detail'].has_key('type'):
    result = True

  return result

def sign_in_to_deep_security():
  """
  Sign in to Deep Security
  """
  global DSM

  if not os.environ.has_key('dsUsername') or not os.environ.has_key('dsPassword'):
    print("dsUsername and dsPassword are REQUIRED environment variables for this AWS Lambda function")
    return None

  ds_username = os.environ['dsUsername']
  ds_password = os.environ['dsPassword']
  ds_tenant = None
  if os.environ.has_key('dsTenant'): ds_tenant = os.environ['dsTenant']
  ds_hostname = None
  if os.environ.has_key('dsHostname'): ds_hostname = os.environ['dsHostname']
  ds_port = None
  if os.environ.has_key('dsPort'): ds_port = os.environ['dsPort']
  ds_ignore_ssl_validation = None
  if os.environ.has_key('dsIgnoreSslValidation'): ds_ignore_ssl_validation = os.environ['dsIgnoreSslValidation']

  try:
    DSM = deepsecurity.dsm.Manager(username=ds_username, password=ds_password, tenant=ds_tenant)
    DSM.sign_in()
    DSM.computers.get()
    DSM.policies.get()
    print("Signed into Deep Security")
  except Exception, ex:
    print("Could not successfully sign into Deep Security. Threw exception: {}".format(ex))

def send_to_slack(message, event):
  """
  Send the specified message to Slack
  """
  if not ENABLE_SLACK:
    print("To enable Slack functionality, add the 'SlackURL' environment variable with the value set to the incoming webhook URL for your desired team/channel")
    return False

  msg = {
    'username': 'Deep Security',
    'icon_url': 'https://raw.githubusercontent.com/deep-security/amazon-guardduty/blob/master/docs/trend-micro.png',
    'text': message,
    "attachments": [
        {
            "fallback": event['detail']['title'],
            "color": "#36a64f",
            "author_name": "Amazon GuardDuty Finding",
            "author_link": "https://github.com/deep-security/amazon-guardduty/",
            "author_icon": "https://raw.githubusercontent.com/deep-security/amazon-guardduty/blob/master/docs/trend-micro.png",
            "title": "{} - {}".format(event['detail']['title'], event['id']),
            "title_link": "https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings/",
            "text": "The finding is of type {} and has beens seen {} times. The last time was at {}".format(event['detail']['type'], event['detail']['service']['count'], event['detail']['service']['eventLastSeen']),
            "fields": [
                {
                    "title": "Priority",
                    "value": event['detail']['severity'],
                    "short": False
                }
            ],
        }
    ]
  }
  request = urllib2.Request(os.environ['slackURL'])
  request.add_header('Content-type', 'application/json')
    
  try:
    response = urllib2.urlopen(request, json.dumps(msg))
    print("Sent message to Slack. Received response {}".format(response))
  except Exception, err:
    print("Could not send the message to Slack. Threw exception: {}".format(err))

def print_event(event):
  try:
        print("Received event: " + json.dumps(event))
  except Exception, ex:
      print(ex)
  try:
      print(event)
  except Exception, ex:
      print(ex)

def get_affected_instance_in_deep_security(instance_id):
  """
  Find and return the specified instance in Deep Security

  Returns a deepsecurity.computers.Computer object or None
  """
  result = None

  if not DSM: return result

  try:
    computers = DSM.computers.find(cloud_object_instance_id=instance_id)
    if len(computers) > 0:
      result = DSM.computers[computers[0]]
      print("Found the instance in Deep Security as computer {}".format(result.name))
  except Exception, ex:
    print("Could not find the instance in Deep Security. Threw exception: {}".format(ex))

  return result

def get_affected_instance_id(event):
  """
  Get the instance ID of the affected instance in the finding
  """
  result = None
  if event.has_key('detail') and event['detail'].has_key('resource') and event['detail']['resource'].has_key('instanceDetails') and event['detail']['resource']['instanceDetails'].has_key('instanceId'):
    result = event['detail']['resource']['instanceDetails']['instanceId']
    print("Finding is specific to instance [{}]".format(result))

  return result

def enable_ips_for_instance_in_ds(instance_in_ds):
  """
  For the specified Computer object, make sure that the IPS is on and active
  """
  result = None
  if instance_in_ds and ENABLE_MODULES and DSM:
    if "on" in instance_in_ds.overall_intrusion_prevention_status.lower():
      # IPS is already on, do nothing
      print("IPS is already active for instance in DS {}".format(instance_in_ds.computer_name))
      result = "already enabled"
    else:
      # turn on the IPS via hostSettingGet() / hostSettingSet()
      print("Enabling IPS for instance in DS {}".format(instance_in_ds.computer_name))
      if DSM.policies.has_key(instance_in_ds.security_profile_id):
        DSM.policies[instance_in_ds.security_profile_id].intrusion_prevention_state = "ON"
        DSM.policies[instance_in_ds.security_profile_id].save()
        print("Updated security policy {} by enabling intrusion prevention".format(DSM.policies[instance_in_ds.security_profile_id].name))
        result = "enabled"

  return result

def enable_am_for_instance_in_ds(instance_in_ds):
  """
  For the specified Computer object, make sure that the anti-malware control is on and active
  """
  result = None
  if instance_in_ds and ENABLE_MODULES and DSM:
    if "on" in instance_in_ds.overall_anti_malware_status.lower():
      # Anti-malware is already on, do nothing
      print("Anti-malware is already active for instance in DS {}".format(instance_in_ds.computer_name))
      result = "already enabled"
    else:
      # turn on the anti-malware via hostSettingGet() / hostSettingSet()
      print("Enabling anti-malware for instance in DS {}".format(instance_in_ds.computer_name))
      if DSM.policies.has_key(instance_in_ds.security_profile_id):
        DSM.policies[instance_in_ds.security_profile_id].anti_malware_state = "ON"
        DSM.policies[instance_in_ds.security_profile_id].save()
        print("Updated security policy {} by enabling anti-malware".format(DSM.policies[instance_in_ds.security_profile_id].name))
        result = "enabled"

  return result

def enable_im_for_instance_in_ds(instance_in_ds):
  """
  For the specified Computer object, make sure that integrity monitoring is on and active
  """
  result = None
  if instance_in_ds and ENABLE_MODULES and DSM:
    if "on" in instance_in_ds.overall_integrity_monitoring_status.lower():
      # IPS is already on, do nothing
      print("Integrity monitoring is already active for instance in DS {}".format(instance_in_ds.computer_name))
      result = "already enabled"
    else:
      # turn on the IPS via hostSettingGet() / hostSettingSet()
      print("Enabling IPS for instance in DS {}".format(instance_in_ds.computer_name))
      if DSM.policies.has_key(instance_in_ds.security_profile_id):
        DSM.policies[instance_in_ds.security_profile_id].integrity_monitoring_state = "ON"
        DSM.policies[instance_in_ds.security_profile_id].save()
        print("Updated security policy {} by enabling integrity monitoring".format(DSM.policies[instance_in_ds.security_profile_id].name))
        result = "enabled"

  return result  

def lambda_handler(event, context):
  if is_event_from_guardduty(event):
    # check the environment variables
    if os.environ.has_key('slackURL'):
      global ENABLE_SLACK
      print("Sending messages to Slack")
      ENABLE_SLACK = True

    if os.environ.has_key('enableModules'):
      global ENABLE_MODULES
      if int(os.environ['enableModules']) == 1:
        print("Enabling Deep Security modules as required")
        ENABLE_MODULES = True

    event_type = event['detail']['type']
    print("Processing Amazon GuardDuty event of type [{}]".format(event_type))

    sign_in_to_deep_security()

    # get the relevant details regardless of action that needs to be taken
    instance_id = get_affected_instance_id(event)
    instance_in_ds = get_affected_instance_in_deep_security(instance_id)
    computer_name = "Instance is not registered in Deep Security" 
    if instance_in_ds and "computer_name" in dir(instance_in_ds):
        computer_name = instance_in_ds.computer_name
    finding_id = event['id']

    # route the event to a specific action
    if event_type.lower() in [
      "Recon:EC2/PortProbeUnprotectedPort".lower(), # EC2 instance has an unprotected port which is being probed by a known malicious host
      "Recon:EC2/Portscan".lower(), # EC2 instance is performing outbound port scans against remote host
      "UnauthorizedAccess:EC2/SSHBruteForce".lower(), # A malicious actor has tried to access the C2 instance over SSH repeatedly
      ]:

      # run a recommendation scan
      if instance_in_ds:
        print("Requested recommendation scan for instance {}".format(instance_id))
        instance_in_ds.scan_for_recommendations()

        # make sure that IPS is on and active
        ips_result = enable_ips_for_instance_in_ds(instance_in_ds)

        msg = "Based on a suspicious <https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings|finding> in Amazon GuardDuty, Deep Security is now scanning computer {} for rule recommendations to ensure the security profile is accurate and up to date.".format(computer_name)
        if ips_result == "already enabled":
          msg += " Intrusion prevention is already active on this instance"
        elif ips_result == "enabled":
          msg += " As a result, Deep Security has now activated intrusion prevention on this instance"

        # run an integrity scan in cases of SSH brute force
        if event_type.lower() == "UnauthorizedAccess:EC2/SSHBruteForce".lower():
          instance_in_ds.scan_for_integrity()
          msg += " Deep Security is also scanning the instance for integrity"
          integrity_result = enable_im_for_instance_in_ds(instance_in_ds)
          if integrity_result == "already enabled":
            msg += " Integrity monitoring is already active on this instance"
          elif ips_result == "enabled":
            msg += " As a result of the finding, Deep Security has now activated integrity monitoring on this instance"

        send_to_slack(msg, event)
      else:
        msg = "Amazon GuardDuty has noticed something suspicious about an EC2 instance running in your account. Deep Security is not protecting the instance. You can resolve this by deploying the Deep Security agent to the instance and activating it"
        send_to_slack(msg, event)

    elif event_type.lower() == "UnauthorizedAccess:EC2/MaliciousIPCaller.Custom".lower(): # EC2 instance is communicating with a disallowed IP address on a threat list
      # run a recommendation scan
      if instance_in_ds:
        print("Requested recommendation scan for instance {}".format(instance_id))
        instance_in_ds.scan_for_recommendations()
    
        # run an integrity scan
        print("Requested integrity scan for instance {}".format(instance_id))
        instance_in_ds.scan_for_integrity()
      
        # run an anti-malware scan
        print("Requested malware scan for instance {}".format(instance_id))
        instance_in_ds.scan_for_malware()

        # make sure that IPS is on and active
        ips_result = enable_ips_for_instance_in_ds(instance_in_ds)

        msg = "Based on a suspicious <https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings|finding> in Amazon GuardDuty, Deep Security is now scanning computer {} for rule recommendations to ensure the security profile is accurate and up to date. Deep Security is also running an integrity scan and a malware scan just in case.".format(computer_name)
        if ips_result == "already enabled":
          msg += " Intrusion prevention is already active on this instance"
        elif ips_result == "enabled":
          msg += " As a result, Deep Security has now activated intrusion prevention on this instance"

        send_to_slack(msg, event)
      else:
        msg = "Amazon GuardDuty has noticed something suspicious about an EC2 instance running in your account. Deep Security is not protecting the instance. You can resolve this by deploying the Deep Security agent to the instance and activating it"
        send_to_slack(msg, event)

    elif "CryptoCurrency".lower() in event_type.lower(): # EC2 instance is communicating with known bitcoin destinations
      # Run an anti-malware scan on the affected instance to make sure it's not infected
      if instance_in_ds:
        print("Requested anti-malware scan for instance {}".format(instance_id))
        instance.scan_for_malware()

        am_result = enable_am_for_instance_in_ds(instance_in_ds)

        msg = "Based on a suspicious <https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings|finding> in Amazon GuardDuty, Deep Security is now scanning computer {} for rule recommendations to ensure the security profile is accurate and up to date.".format(computer_name)
        if am_result == "already enabled":
          msg += " Anti-malware protection is already active on this instance"
        elif am_result == "enabled":
          msg += " As a result, Deep Security has now activated anti-malware protection on this instance"
        send_to_slack(msg, event)
      else:
        msg = "Amazon GuardDuty has noticed something suspicious about an EC2 instance running in your account. Deep Security is not protecting the instance. You can resolve this by deploying the Deep Security agent to the instance and activating it"
        send_to_slack(msg, event)

    elif event_type.lower() in [
      "Backdoor:EC2".lower(), # the EC2 instance my be compromised in some way by malicious software
      "Trojan:EC2".lower(), # the EC2 instance my be compromised in some way by malicious software
      ]:
      # Run an anti-malware scan on the affected instance to make sure it's not infected
      if instance_in_ds:
        print("Requested anti-malware scan for instance {}".format(instance_id))
        instance.scan_for_malware()

        am_result = enable_am_for_instance_in_ds(instance_in_ds)

        # run an integrity scan
        print("Requested integrity scan for instance {}".format(instance_id))
        instance_in_ds.scan_for_integrity()

        msg = "Based on a suspicious <https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings|finding> in Amazon GuardDuty, Deep Security is now scanning computer {} for file integrity and malware.".format(computer_name)
        if am_result == "already enabled":
          msg += " Anti-malware protection is already active on this instance"
        elif am_result == "enabled":
          msg += " As a result, Deep Security has now activated anti-malware protection on this instance"
        send_to_slack(msg, event)
      else:
        msg = "Amazon GuardDuty has noticed something suspicious about an EC2 instance running in your account. Deep Security is not protecting the instance. You can resolve this by deploying the Deep Security agent to the instance and activating it"
        send_to_slack(msg, event)

    else:
      msg = "Amazon GuardDuty generated a <https://gd-preview.us-east-1.aws.amazon.com/guardduty/home?#/findings|finding>. Details are available within the Amazon GuardDuty Management Console"
      send_to_slack(msg, event)
        

    # clean up
    if DSM and "sign_out" in dir(DSM):
      try:
        DSM.sign_out()
      except Exception, ex: pass
  else:
    print("Event received is not from Amazon GuardDuty")