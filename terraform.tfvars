// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0



# Sample Values, modify accordingly

knowledge_base_name             = "bedrock-kb"
enable_access_logging           = true
enable_s3_lifecycle_policies    = true
enable_endpoints                = true
knowledge_base_model_id         = "amazon.titan-embed-text-v2:0"
app_name                        = "secbot"
env_name                        = "dev"
app_region                      = "usw2"
agent_model_id                  = "anthropic.claude-3-haiku-20240307-v1:0"
bedrock_agent_invoke_log_bucket = "bedrock-agent-bucket-new"
agent_name                      = "security-bedrock-agent"
agent_alias_name                = "security-bedrock-agent-alias"
agent_action_group_name         = "security-bedrock-agent-ag"
aoss_collection_name            = "aoss-collection"
aoss_collection_type            = "VECTORSEARCH"
agent_instructions              = <<-EOT
You are a cloud security expert bot with knowledge of the AWS Well-Architected Framework.
 - Identify EC2 instances that are non-compliant according to the AWS Config rules. Ask the user to input the config rule name.
 - The Lambda function will check for non-compliant EC2 instances and return their instance IDs.
 - If non-compliant instances are found, provide the following options to the user:
 1. Pause non-compliant ec2 instances.
 2. Remediate non-compliant resources (e.g., changing instance types or taking corrective actions).
 -Allow the user to select one of these options and take the corresponding action.
 - If all instances are compliant, respond by saying that all instances are compliant.
 - Store relevant session attributes, such as the rule name, query type, and the user's selected action, for future reference in the current session.
 - If the user chooses to pause resources, check again and ensure the instances are paused and confirm with a message. If they are already paused, notify the user saying that the instances are paused. Do not make additional comments.
 - If the user chooses to remediate, apply the necessary actions to make the instances compliant and confirm when the remediation is successful.
 - Additionally, provide insights and recommendations on AWS cloud security based on the AWS Well-Architected Framework Security Pillar. This includes information on best practices for securing AWS workloads, identity and access management (IAM), detective controls, infrastructure protection, data protection, and incident response.
 - Respond to user queries regarding AWS security best practices, highlighting key principles from the Well-Architected Framework Security Pillar when applicable.
EOT
agent_description               = "Security related agent"
agent_actiongroup_descrption    = "Security related action group"
kb_instructions_for_agent       = "Use the knowledge base when the user is asking for a definition about a fitness, diet plans. Give a very detailed answer and cite the source."
kms_key_id                      = "xxxxxxxxxxx"
vpc_subnet_ids                  = ["subnet-xxxxxxx", "subnet-xxxxxxx"]
vpc_id                          = "vpc-xxxxxxxx"
cidr_blocks_sg                  = ["****", "***"]
code_base_zip                   = "lambda_function.zip"
code_base_bucket                = "codebasebucket-4"
enable_guardrails               = true
# guardrail_name                      = "bedrock-guardrail"
# guardrail_blocked_input_messaging   = "This input is not allowed due to content restrictions."
# guardrail_blocked_outputs_messaging = "The generated output was blocked due to content restrictions."
# guardrail_description               = "A guardrail for Bedrock to ensure safe and appropriate content"
# guardrail_content_policy_config = [
#   {
#     filters_config = [
#       {
#         input_strength  = "MEDIUM"
#         output_strength = "MEDIUM"
#         type            = "HATE"
#       },
#       {
#         input_strength  = "HIGH"
#         output_strength = "HIGH"
#         type            = "VIOLENCE"
#       }
#     ]
#   }
# ]
# guardrail_sensitive_information_policy_config = [
#   {
#     pii_entities_config = [
#       {
#         action = "BLOCK"
#         type   = "NAME"
#       },
#       {
#         action = "BLOCK"
#         type   = "EMAIL"
#       }
#     ],
#     regexes_config = [
#       {
#         action      = "BLOCK"
#         description = "Block Social Security Numbers"
#         name        = "SSN_Regex"
#         pattern     = "^\\d{3}-\\d{2}-\\d{4}$"
#       }
#     ]
#   }
# ]
# guardrail_topic_policy_config = [
#   {
#     topics_config = [
#       {
#         name       = "investment_advice"
#         examples   = ["Where should I invest my money?", "What stocks should I buy?"]
#         type       = "DENY"
#         definition = "Any advice or recommendations regarding financial investments or asset allocation."
#       }
#     ]
#   }
# ]
# guardrail_word_policy_config = [
#   {
#     managed_word_lists_config = [
#       {
#         type = "PROFANITY"
#       }
#     ],
#     words_config = [
#       {
#         text = "badword1"
#       },
#       {
#         text = "badword2"
#       }
#     ]
#   }
# ]